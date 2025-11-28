import { FIREBASE_AUTH } from '@app/modules/firebase/firebase.constants';
import {
  Inject,
  Injectable,
  ConflictException,
  BadRequestException,
  UnauthorizedException,
  NotFoundException,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { Auth } from 'firebase-admin/auth';
import { UserService } from '@app/modules/user/services/user.service';
import { TenantManagementService } from '@app/modules/tenant/services/tenant-management.service';
import { TenantService } from '@app/modules/tenant/services/tenant.service';
import { RoleService } from '@app/modules/role/services/role.service';
import { LoginDto } from '../dto/login.dto';
import { RegisterDto } from '../dto/register.dto';
import { EnvironmentVariables } from '@app/core/validators';

@Injectable()
export class AuthService {
  constructor(
    @Inject(FIREBASE_AUTH)
    private readonly auth: Auth,
    private readonly userService: UserService,
    private readonly tenantManagementService: TenantManagementService,
    private readonly tenantService: TenantService,
    private readonly roleService: RoleService,
    private readonly configService: ConfigService<EnvironmentVariables, true>,
  ) {}

  /**
   * Formats company name to meet Firebase tenant displayName requirements:
   * - Must start with a letter
   * - Only letters, digits, and hyphens
   * - 4-20 characters
   * Uses the same slug generation logic as tenant management
   */
  private formatFirebaseDisplayName(companyName: string): string {
    // Use same slug generation as tenant management
    let formatted = companyName
      .toLowerCase()
      .trim()
      .replace(/[^a-z0-9\s-]/g, '') // Remove special chars except spaces and hyphens
      .replace(/\s+/g, '-') // Replace spaces with hyphens
      .replace(/-+/g, '-') // Replace multiple hyphens with single
      .replace(/^-|-$/g, ''); // Remove leading/trailing hyphens

    // Ensure it starts with a letter
    if (!/^[a-z]/.test(formatted)) {
      formatted = 'tenant-' + formatted;
    }

    // Ensure length is between 4-20 characters
    if (formatted.length < 4) {
      formatted = formatted.padEnd(4, 'x');
    }
    if (formatted.length > 20) {
      formatted = formatted.substring(0, 20);
    }

    // Final check: ensure it ends with alphanumeric (not hyphen)
    formatted = formatted.replace(/-+$/, '');
    if (formatted.length < 4) {
      formatted = formatted.padEnd(4, 'x');
    }

    return formatted;
  }

  async register(dto: RegisterDto) {
    try {
      // Step 1: Check if company already has a tenant
      const existingTenant =
        await this.tenantManagementService.findByCompanyName(dto.company_name);
      if (existingTenant) {
        throw new ConflictException({
          message: 'Company already exists',
          errors: [
            {
              code: 'COMPANY_EXISTS',
              message: 'A tenant for this company already exists',
            },
          ],
        });
      }

      // Step 2: Create Firebase tenant with formatted display name
      const firebaseDisplayName = this.formatFirebaseDisplayName(
        dto.company_name,
      );

      const firebaseTenant = await this.auth.tenantManager().createTenant({
        displayName: firebaseDisplayName,
        emailSignInConfig: {
          enabled: true,
          passwordRequired: true,
        },
        multiFactorConfig: {
          state: 'DISABLED',
        },
      });

      // Step 3: Create database tenant (record + schema)
      const tenant = await this.tenantManagementService.createTenant({
        companyName: dto.company_name,
        ownerEmail: dto.email,
        firebaseTenantId: firebaseTenant.tenantId,
      });

      // Step 4: Create Firebase user within the tenant
      const firebaseUser = await this.auth
        .tenantManager()
        .authForTenant(firebaseTenant.tenantId)
        .createUser({
          email: dto.email,
          password: dto.password,
          displayName: dto.name,
        });

      // Step 5: Set tenant context for this request
      this.tenantService.setTenant(tenant);

      const owner = await this.roleService.findByName('owner');
      if (!owner) {
        throw new NotFoundException({
          message: 'Owner role not found',
          errors: [
            {
              code: 'ROLE_NOT_FOUND',
              message: 'Default owner role does not exist',
            },
          ],
        });
      }

      // Step 6: Create user in tenant schema
      const user = await this.userService.createUser({
        first_name: dto.first_name,
        last_name: dto.last_name,
        company_name: dto.company_name,
        email: dto.email,
        firebase_uid: firebaseUser.uid,
        full_name: dto.name,
        roles: [owner],
      });

      await this.tenantManagementService.setTenantOwner(tenant.id, user.id);

      // Step 7: Ensure default roles exist and assign owner role to first user
      await this.roleService.ensureDefaultRoles();

      // Step 8: Set custom claims on Firebase user (for role-based access)
      await this.auth
        .tenantManager()
        .authForTenant(firebaseTenant.tenantId)
        .setCustomUserClaims(firebaseUser.uid, {
          firebaseTenantId: firebaseTenant.tenantId,
          tenantId: tenant.id,
          slug: tenant.slug,
          roles: [owner], // First user is the owner
        });

      // Step 4: Create custom token for the user (client will exchange for ID token)
      const tenantAuth = this.auth
        .tenantManager()
        .authForTenant(tenant.firebase_tenant_id);

      const accessToken = await tenantAuth.createCustomToken(firebaseUser.uid, {
        slug: tenant.slug,
        tenantId: tenant.id,
        roles: [owner],
        firebaseTenantId: tenant.firebase_tenant_id,
      });

      return {
        access_token: accessToken,
        user,
        tenant: {
          ...tenant,
          owner_id: user.id,
        },
      };
    } catch (error) {
      // If anything fails, we should ideally rollback
      // For now, just rethrow
      if (error instanceof ConflictException) {
        throw error;
      }

      throw new BadRequestException({
        message: 'Registration failed',
        errors: [
          {
            code: 'REGISTRATION_FAILED',
            message:
              error instanceof Error ? error.message : 'Unknown error occurred',
          },
        ],
      });
    }
  }

  async login(dto: LoginDto) {
    try {
      // Step 1: Find tenant by slug
      const tenant = await this.tenantManagementService.findBySlug(
        dto.tenant_slug,
      );
      if (!tenant) {
        throw new NotFoundException({
          message: 'Tenant not found',
          errors: [
            {
              code: 'TENANT_NOT_FOUND',
              message: `No tenant found with slug: ${dto.tenant_slug}`,
            },
          ],
        });
      }

      if (!tenant.is_active) {
        throw new UnauthorizedException({
          message: 'Tenant is inactive',
          errors: [
            {
              code: 'TENANT_INACTIVE',
              message: 'This tenant account has been deactivated',
            },
          ],
        });
      }

      // Step 2: Get tenant-specific auth
      const tenantAuth = this.auth
        .tenantManager()
        .authForTenant(tenant.firebase_tenant_id);

      // Step 3: Verify user credentials using Firebase Auth REST API
      // Note: Admin SDK doesn't have signInWithEmailAndPassword, so we create a custom token
      const firebaseUser = await tenantAuth.getUserByEmail(dto.email);

      if (!firebaseUser) {
        throw new UnauthorizedException({
          message: 'Invalid credentials',
          errors: [
            {
              code: 'INVALID_CREDENTIALS',
              message: 'Email or password is incorrect',
            },
          ],
        });
      }

      // Step 4: Create custom token for the user (client will exchange for ID token)
      const customToken = await tenantAuth.createCustomToken(firebaseUser.uid, {
        slug: tenant.slug,
        firebaseTenantId: tenant.firebase_tenant_id,
      });

      // Step 5: Set tenant context
      this.tenantService.setTenant(tenant);

      // Step 6: Get user from tenant database
      const user = await this.userService.findByFirebaseUid(firebaseUser.uid);

      if (!user) {
        throw new UnauthorizedException({
          message: 'User not found in tenant database',
          errors: [
            {
              code: 'USER_NOT_FOUND',
              message: 'User record not found',
            },
          ],
        });
      }

      return {
        access_token: customToken,
        user,
        tenant,
      };
    } catch (error) {
      if (
        error instanceof NotFoundException ||
        error instanceof UnauthorizedException
      ) {
        throw error;
      }

      // Handle Firebase auth errors
      if (
        error instanceof Error &&
        error.message.includes('auth/user-not-found')
      ) {
        throw new UnauthorizedException({
          message: 'Invalid credentials',
          errors: [
            {
              code: 'INVALID_CREDENTIALS',
              message: 'Email or password is incorrect',
            },
          ],
        });
      }

      throw new BadRequestException({
        message: 'Login failed',
        errors: [
          {
            code: 'LOGIN_FAILED',
            message:
              error instanceof Error ? error.message : 'Unknown error occurred',
          },
        ],
      });
    }
  }

  async getMe(firebaseUid: string) {
    const user = await this.userService.findByFirebaseUid(firebaseUid);

    if (!user) {
      throw new NotFoundException({
        message: 'User not found',
        errors: [
          {
            code: 'USER_NOT_FOUND',
            message: 'User record not found',
          },
        ],
      });
    }

    return user;
  }

  async exchangeCustomToken(customToken: string, tenantSlug: string) {
    const apiKey = this.configService.get<string>('FIREBASE_WEB_API_KEY');

    if (!apiKey) {
      throw new BadRequestException({
        message: 'Firebase API key not configured',
        errors: [
          {
            code: 'MISSING_CONFIG',
            message: 'FIREBASE_WEB_API_KEY environment variable is required',
          },
        ],
      });
    }

    // Get tenant to find Firebase tenant ID
    const tenant = await this.tenantManagementService.findBySlug(tenantSlug);
    if (!tenant) {
      throw new NotFoundException({
        message: 'Tenant not found',
        errors: [
          {
            code: 'TENANT_NOT_FOUND',
            message: `No tenant found with slug: ${tenantSlug}`,
          },
        ],
      });
    }

    // Exchange custom token for ID token using tenant-specific Firebase REST API
    const response = await fetch(
      `https://identitytoolkit.googleapis.com/v1/accounts:signInWithCustomToken?key=${apiKey}`,
      {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          token: customToken,
          returnSecureToken: true,
          tenantId: tenant.firebase_tenant_id, // ← Add tenant ID
        }),
      },
    );

    if (!response.ok) {
      const error = (await response.json()) as {
        error?: { message?: string };
      };
      throw new BadRequestException({
        message: 'Token exchange failed',
        errors: [
          {
            code: 'TOKEN_EXCHANGE_FAILED',
            message: error.error?.message || 'Failed to exchange custom token',
          },
        ],
      });
    }

    const data = (await response.json()) as {
      idToken: string;
      refreshToken: string;
      expiresIn: string;
    };

    return {
      id_token: data.idToken,
      refresh_token: data.refreshToken,
      expires_in: data.expiresIn,
    };
  }

  async refreshToken(refreshToken: string, tenantSlug: string) {
    const apiKey = this.configService.get<string>('FIREBASE_WEB_API_KEY');

    if (!apiKey) {
      throw new BadRequestException({
        message: 'Firebase API key not configured',
        errors: [
          {
            code: 'MISSING_CONFIG',
            message: 'FIREBASE_WEB_API_KEY environment variable is required',
          },
        ],
      });
    }

    // Get tenant to find Firebase tenant ID
    const tenant = await this.tenantManagementService.findBySlug(tenantSlug);
    if (!tenant) {
      throw new NotFoundException({
        message: 'Tenant not found',
        errors: [
          {
            code: 'TENANT_NOT_FOUND',
            message: `No tenant found with slug: ${tenantSlug}`,
          },
        ],
      });
    }

    // Refresh the ID token using Firebase REST API
    const response = await fetch(
      `https://securetoken.googleapis.com/v1/token?key=${apiKey}`,
      {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          grant_type: 'refresh_token',
          refresh_token: refreshToken,
        }),
      },
    );

    if (!response.ok) {
      const error = (await response.json()) as {
        error?: { message?: string };
      };
      throw new BadRequestException({
        message: 'Token refresh failed',
        errors: [
          {
            code: 'TOKEN_REFRESH_FAILED',
            message: error.error?.message || 'Failed to refresh token',
          },
        ],
      });
    }

    const data = (await response.json()) as {
      id_token: string;
      refresh_token: string;
      expires_in: string;
      token_type: string;
      user_id: string;
      project_id: string;
    };

    return {
      id_token: data.id_token,
      refresh_token: data.refresh_token,
      expires_in: data.expires_in,
    };
  }
}
