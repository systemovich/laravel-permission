<?php

namespace Spatie\Permission\Traits;

use Spatie\Permission\Guard;
use Illuminate\Support\Collection;
use Illuminate\Database\Eloquent\Builder;
use Spatie\Permission\PermissionRegistrar;
use Spatie\Permission\Contracts\Permission;
use Spatie\Permission\Contracts\Restrictable;
use Spatie\Permission\Exceptions\GuardDoesNotMatch;
use Illuminate\Database\Eloquent\Relations\Relation;
use Illuminate\Database\Eloquent\Relations\MorphToMany;
use Spatie\Permission\Exceptions\PermissionDoesNotExist;
use Illuminate\Database\Eloquent\Relations\BelongsToMany;

trait HasPermissions
{
    private $permissionClass;

    public static function bootHasPermissions()
    {
        static::deleting(function ($model) {
            if (method_exists($model, 'isForceDeleting') && ! $model->isForceDeleting()) {
                return;
            }

            $model->permissions()->detach();
        });
    }

    public function getPermissionClass()
    {
        if (! isset($this->permissionClass)) {
            $this->permissionClass = app(PermissionRegistrar::class)->getPermissionClass();
        }

        return $this->permissionClass;
    }

    /**
     * A model may have multiple direct permissions.
     */
    abstract public function permissions(): BelongsToMany;

    /**
     * Scope the model query to certain permissions only.
     *
     * @param \Illuminate\Database\Eloquent\Builder $query
     * @param string|array|\Spatie\Permission\Contracts\Permission|\Illuminate\Support\Collection $permissions
     *
     * @return \Illuminate\Database\Eloquent\Builder
     */
    public function scopePermission(Builder $query, $permissions): Builder
    {
        $permissions = $this->convertToPermissionModels($permissions);

        $rolesWithPermissions = array_unique(array_reduce($permissions, function ($result, $permission) {
            return array_merge($result, $permission->roles->all());
        }, []));

        return $query->where(function ($query) use ($permissions, $rolesWithPermissions) {
            $query->whereHas('permissions', function ($query) use ($permissions) {
                $query->where(function ($query) use ($permissions) {
                    foreach ($permissions as $permission) {
                        $query->orWhere(config('permission.table_names.permissions').'.id', $permission->id);
                    }
                });
            });
            if (count($rolesWithPermissions) > 0) {
                $query->orWhereHas('roles', function ($query) use ($rolesWithPermissions) {
                    $query->where(function ($query) use ($rolesWithPermissions) {
                        foreach ($rolesWithPermissions as $role) {
                            $query->orWhere(config('permission.table_names.roles').'.id', $role->id);
                        }
                    });
                });
            }
        });
    }

    /**
     * @param string|array|\Spatie\Permission\Contracts\Permission|\Illuminate\Support\Collection $permissions
     *
     * @return array
     */
    protected function convertToPermissionModels($permissions): array
    {
        if ($permissions instanceof Collection) {
            $permissions = $permissions->all();
        }

        $permissions = array_wrap($permissions);

        return array_map(function ($permission) {
            if ($permission instanceof Permission) {
                return $permission;
            }

            return $this->getPermissionClass()->findByName($permission, $this->getDefaultGuardName());
        }, $permissions);
    }

    /**
     * Determine if the model may perform the given permission.
     *
     * @param string|int|\Spatie\Permission\Contracts\Permission $permission
     * @param string|null $guardName
     *
     * @return bool
     */
    public function hasPermissionTo($permission, $guardName = null, Restrictable $restrictable = null): bool
    {
        $permissionClass = $this->getPermissionClass();

        if (is_string($permission)) {
            $permission = $permissionClass->findByName(
                $permission,
                $guardName ?? $this->getDefaultGuardName()
            );
        }

        if (is_int($permission)) {
            $permission = $permissionClass->findById(
                $permission,
                $guardName ?? $this->getDefaultGuardName()
            );
        }

        if (! $permission instanceof Permission) {
            throw new PermissionDoesNotExist;
        }

        return $this->hasDirectPermission($permission, $restrictable) || $this->hasPermissionViaRole($permission, $restrictable);
    }

    /**
     * Determine if the model has any of the given permissions.
     *
     * @param array ...$permissions
     *
     * @return bool
     */
    public function hasAnyPermission($permissions, Restrictable $restrictable = null): bool
    {
        if (is_array($permissions[0])) {
            $permissions = $permissions[0];
        }

        foreach ($permissions as $permission) {
            if ($this->hasPermissionTo($permission, null, $restrictable)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Determine if the model has all of the given permissions.
     *
     * @param array ...$permissions
     *
     * @return bool
     */
    public function hasAllPermissions(...$permissions): bool
    {
        if (is_array($permissions[0])) {
            $permissions = $permissions[0];
        }

        foreach ($permissions as $permission) {
            if (! $this->hasPermissionTo($permission)) {
                return false;
            }
        }

        return true;
    }

    /**
     * Determine if the model has, via roles, the given permission.
     *
     * @param \Spatie\Permission\Contracts\Permission $permission
     *
     * @return bool
     */
    protected function hasPermissionViaRole(Permission $permission, Restrictable $restrictable = null): bool
    {
        return $this->hasRole($permission->roles, $restrictable);
    }

    /**
     * Determine if the model has the given permission.
     *
     * @param string|int|\Spatie\Permission\Contracts\Permission $permission
     *
     * @return bool
     */
    public function hasDirectPermission($permission, Restrictable $restrictable = null): bool
    {
        $permissionClass = $this->getPermissionClass();

        if (is_string($permission)) {
            $permission = $permissionClass->findByName($permission, $this->getDefaultGuardName());
            if (! $permission) {
                return false;
            }
        }

        if (is_int($permission)) {
            $permission = $permissionClass->findById($permission, $this->getDefaultGuardName());
            if (! $permission) {
                return false;
            }
        }

        if (! $permission instanceof Permission) {
            return false;
        }

         // Needed to preserve the caching mechanism at least for the not scoped permissions
        return (is_null($restrictable) ? $this->permissions : $this->permissions($restrictable)->get())
            ->contains('id', $permission->id);
    }

    /**
     * Return all the permissions the model has via roles.
     */
    public function getPermissionsViaRoles(Restrictable $restrictable = null): Collection
    {
        $this->load('roles', 'roles.permissions');
        return (is_null($restrictable) ? $this->roles : $this->roles($restrictable)->get())
            ->flatMap(function ($role) {
                return $role->permissions;
            })->sort()->values();
    }

    /**
     * Return all the permissions the model has, both directly and via roles.
     */
    public function getAllPermissions(Restrictable $restrictable = null): Collection
    {
        return $this->getDirectPermission($restrictable)
            ->merge($this->getPermissionsViaRoles($restrictable))
            ->sort()
            ->values();
    }

    /**
     * Grant the given permission(s) to a role.
     *
     * @param string|array|\Spatie\Permission\Contracts\Permission|\Illuminate\Support\Collection $permissions
     * @param \Spatie\Permission\Contracts\Restritable|null $restrictable
     *
     * @return $this
     */
    public function givePermissionTo($permissions, Restrictable $restrictable = null)
    {
        // Permission objects, if directly collected, becomes arrays of fields and the flatten() messes with
        // the map function giving every single Permission field as parameter for getStoredPermission.
        // To avoid this, if a Permission is given an empty collection is created and the permission is pushed inside.
        // In this way, in case of a Permission instance, the object is not flattened,
        // but for arrays, collections and string everything works as expected.
        $permissions = (($permissions instanceof Permission) ? collect()->push($permissions) : collect($permissions))
            ->flatten()
            ->map(function ($permission) {
                return $this->getStoredPermission($permission);
            })
            ->filter(function ($permission) {
                return $permission instanceof Permission;
            })
            ->each(function ($permission) {
                $this->ensureModelSharesGuard($permission);
            })
            ->map->id
            ->all();

        $model = $this->getModel();

        if ($model->exists) {
            if (! is_null($restrictable)) {
                $permissions = $permissions->map(function ($permission) use ($restrictable) {
                    return [
                        $permission => [
                            'restrictable_id' => $restrictable->getRestrictableId(),
                            'restrictable_type' => $restrictable->getRestrictableTable(),
                        ]
                    ];
                });
            }
            $this->permissions()->sync($permissions, false);
        } else {
            $class = \get_class($model);

            $class::saved(function ($model) use ($permissions, $restrictable) {
                $model->permissions()->attach($permissions, is_null($restrictable) ? [] : [
                    'restrictable_id' => $restrictable->getRestrictableId(),
                    'restrictable_type' => $restrictable->getRestrictableTable(),
                ], false);
            });
        }

        $this->forgetCachedPermissions();

        return $this;
    }

    /**
     * Remove all current permissions and set the given ones.
     *
     * @param string|array|\Spatie\Permission\Contracts\Permission|\Illuminate\Support\Collection $permissions
     * @param \Spatie\Permission\Contracts\Restrictable $restrictable
     *
     * @return $this
     */
    public function syncPermissions($permissions, Restrictable $restrictable = null)
    {
        $this->permissions($restrictable)->detach();

        return $this->givePermissionTo($permissions, $restrictable);
    }

    /**
     * Revoke the given permission.
     *
     * @param \Spatie\Permission\Contracts\Permission|\Spatie\Permission\Contracts\Permission[]|string|string[] $permission
     * @param \Spatie\Permission\Contracts\Restrictable $restrictable
     *
     * @return $this
     */
    public function revokePermissionTo($permission, Restrictable $restrictable = null)
    {
        $this->permissions($restrictable)->detach($this->getStoredPermission($permission)->id);

        $this->forgetCachedPermissions();

        return $this;
    }

    /**
     * @param string|array|\Spatie\Permission\Contracts\Permission|\Illuminate\Support\Collection $permissions
     *
     * @return \Spatie\Permission\Contracts\Permission|\Spatie\Permission\Contracts\Permission[]|\Illuminate\Support\Collection
     */
    protected function getStoredPermission($permissions)
    {
        $permissionClass = $this->getPermissionClass();

        if (is_numeric($permissions)) {
            return $permissionClass->findById($permissions, $this->getDefaultGuardName());
        }

        if (is_string($permissions)) {
            return $permissionClass->findByName($permissions, $this->getDefaultGuardName());
        }

        if (is_array($permissions)) {
            return $permissionClass
                ->whereIn('name', $permissions)
                ->whereIn('guard_name', $this->getGuardNames())
                ->get();
        }

        return $permissions;
    }

    /**
     * @param \Spatie\Permission\Contracts\Permission|\Spatie\Permission\Contracts\Role $roleOrPermission
     *
     * @throws \Spatie\Permission\Exceptions\GuardDoesNotMatch
     */
    protected function ensureModelSharesGuard($roleOrPermission)
    {
        if (! $this->getGuardNames()->contains($roleOrPermission->guard_name)) {
            throw GuardDoesNotMatch::create($roleOrPermission->guard_name, $this->getGuardNames());
        }
    }

    protected function getGuardNames(): Collection
    {
        return Guard::getNames($this);
    }

    protected function getDefaultGuardName(): string
    {
        return Guard::getDefaultName($this);
    }

    /**
     * Forget the cached permissions.
     */
    public function forgetCachedPermissions()
    {
        app(PermissionRegistrar::class)->forgetCachedPermissions();
    }
}
