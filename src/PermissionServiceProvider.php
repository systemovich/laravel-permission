<?php

namespace Spatie\Permission;

use Illuminate\Support\ServiceProvider;
use Illuminate\View\Compilers\BladeCompiler;
use Spatie\Permission\Contracts\Role as RoleContract;
use Spatie\Permission\Contracts\Permission as PermissionContract;

class PermissionServiceProvider extends ServiceProvider
{
    public function boot(PermissionRegistrar $permissionLoader)
    {
        if (isNotLumen()) {
            $this->publishes([
                __DIR__.'/../config/permission.php' => config_path('permission.php'),
            ], 'config');

            if (! class_exists('CreatePermissionTables')) {
                $timestamp = date('Y_m_d_His', time());

                $this->publishes([
                    __DIR__.'/../database/migrations/create_permission_tables.php.stub' => $this->app->databasePath()."/migrations/{$timestamp}_create_permission_tables.php",
                ], 'migrations');
            }
        }

        if ($this->app->runningInConsole()) {
            $this->commands([
                Commands\CreateRole::class,
                Commands\CreatePermission::class,
            ]);
        }

        $this->registerModelBindings();

        $permissionLoader->registerPermissions();
    }

    public function register()
    {
        if (isNotLumen()) {
            $this->mergeConfigFrom(
                __DIR__.'/../config/permission.php',
                'permission'
            );
        }

        $this->registerBladeExtensions();
    }

    protected function registerModelBindings()
    {
        $config = $this->app->config['permission.models'];

        $this->app->bind(PermissionContract::class, $config['permission']);
        $this->app->bind(RoleContract::class, $config['role']);
    }

    protected function registerBladeExtensions()
    {
        $this->app->afterResolving('blade.compiler', function (BladeCompiler $bladeCompiler) {
            $bladeCompiler->directive('role', function ($arguments) {
                $arguments = explode(',', $arguments);
                $role = $arguments[0];
                $guard = $arguments[1] ?? '';
                $restrictableClass = $arguments[2] ?? null;
                $restrictableId = $arguments[3] ?? null;
                $restrictable = "null";

                if ($restrictableId !== null && $restrictableClass !== null) {
                    $restrictable = "{$restrictableClass}::find({$restrictableId})";
                }

                return "<?php if(auth({$guard})->check() && auth({$guard})->user()->hasRole({$role},{$restrictable})): ?>";
            });
            $bladeCompiler->directive('elserole', function ($arguments) {
                list($role, $guard) = explode(',', $arguments.',');

                return "<?php elseif(auth({$guard})->check() && auth({$guard})->user()->hasRole({$role})): ?>";
            });
            $bladeCompiler->directive('endrole', function () {
                return '<?php endif; ?>';
            });

            $bladeCompiler->directive('hasrole', function ($arguments) {
                $arguments = explode(',', $arguments);
                $role = $arguments[0];
                $guard = $arguments[1] ?? '';
                $restrictableClass = $arguments[2] ?? null;
                $restrictableId = $arguments[3] ?? null;
                $restrictable = "null";

                if ($restrictableId !== null && $restrictableClass !== null) {
                    $restrictable = "{$restrictableClass}::find({$restrictableId})";
                }

                return "<?php if(auth({$guard})->check() && auth({$guard})->user()->hasRole({$role},{$restrictable})): ?>";
            });
            $bladeCompiler->directive('endhasrole', function () {
                return '<?php endif; ?>';
            });

            $bladeCompiler->directive('hasanyrole', function ($arguments) {
                $arguments = explode(',', $arguments);
                $roles = $arguments[0];
                $guard = $arguments[1] ?? '';
                $restrictableClass = $arguments[2] ?? null;
                $restrictableId = $arguments[3] ?? null;
                $restrictable = "null";

                if ($restrictableId !== null && $restrictableClass !== null) {
                    $restrictable = "{$restrictableClass}::find({$restrictableId})";
                }

                return "<?php if(auth({$guard})->check() && auth({$guard})->user()->hasAnyRole({$roles},{$restrictable})): ?>";
            });
            $bladeCompiler->directive('endhasanyrole', function () {
                return '<?php endif; ?>';
            });

            $bladeCompiler->directive('hasallroles', function ($arguments) {
                $arguments = explode(',', $arguments);
                $roles = $arguments[0];
                $guard = $arguments[1] ?? '';
                $restrictableClass = $arguments[2] ?? null;
                $restrictableId = $arguments[3] ?? null;
                $restrictable = "null";

                if ($restrictableId !== null && $restrictableClass !== null) {
                    $restrictable = "{$restrictableClass}::find({$restrictableId})";
                }

                return "<?php if(auth({$guard})->check() && auth({$guard})->user()->hasAllRoles({$roles},{$restrictable})): ?>";
            });
            $bladeCompiler->directive('endhasallroles', function () {
                return '<?php endif; ?>';
            });

            $bladeCompiler->directive('unlessrole', function ($arguments) {
                list($role, $guard) = explode(',', $arguments.',');

                return "<?php if(!auth({$guard})->check() || ! auth({$guard})->user()->hasRole({$role})): ?>";
            });
            $bladeCompiler->directive('endunlessrole', function () {
                return '<?php endif; ?>';
            });
        });
    }
}
