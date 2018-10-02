<?php

namespace Spatie\Permission\Traits;

use Illuminate\Support\Collection;
use Spatie\Permission\Contracts\Role;
use Illuminate\Database\Eloquent\Builder;
use Spatie\Permission\PermissionRegistrar;
use Illuminate\Database\Eloquent\Relations\MorphToMany;
use Spatie\Permission\Contracts\Restrictable;

trait HasRoles
{
    use HasPermissions;

    private $roleClass;

    public static function bootHasRoles()
    {
        static::deleting(function ($model) {
            if (method_exists($model, 'isForceDeleting') && ! $model->isForceDeleting()) {
                return;
            }

            $model->roles()->detach();
        });
    }

    public function getRoleClass()
    {
        if (! isset($this->roleClass)) {
            $this->roleClass = app(PermissionRegistrar::class)->getRoleClass();
        }

        return $this->roleClass;
    }

    /**
     * A model may have multiple roles.
     *
     * @param \Spatie\Permission\Contracts\Restrictable|null $restrictable
     */
    public function roles(Restrictable $restrictable = null): MorphToMany
    {
        return $this->morphToMany(
            config('permission.models.role'),
            'model',
            config('permission.table_names.model_has_roles'),
            config('permission.column_names.model_morph_key'),
            'role_id'
        )->withPivot('restrictable_id', 'restrictable_type')
        ->wherePivot('restrictable_id', is_null($restrictable) ? null : $restrictable->getRestrictableId())
        ->wherePivot('restrictable_type', is_null($restrictable) ? null : $restrictable->getRestrictableTable());
    }

    /**
     * A model may have multiple direct permissions.
     */
    public function permissions(Restrictable $restrictable = null): MorphToMany
    {
        return $this->morphToMany(
            config('permission.models.permission'),
            'model',
            config('permission.table_names.model_has_permissions'),
            config('permission.column_names.model_morph_key'),
            'permission_id'
        )->withPivot('restrictable_id', 'restrictable_type')
        ->wherePivot('restrictable_id', is_null($restrictable) ? null : $restrictable->getRestrictableId())
        ->wherePivot('restrictable_type', is_null($restrictable) ? null : $restrictable->getRestrictableTable());
    }

    /**
     * Scope the model query to certain roles only.
     *
     * @param \Illuminate\Database\Eloquent\Builder $query
     * @param string|array|\Spatie\Permission\Contracts\Role|\Illuminate\Support\Collection $roles
     *
     * @return \Illuminate\Database\Eloquent\Builder
     */
    public function scopeRole(Builder $query, $roles): Builder
    {
        if ($roles instanceof Collection) {
            $roles = $roles->all();
        }

        if (! is_array($roles)) {
            $roles = [$roles];
        }

        $roles = array_map(function ($role) {
            if ($role instanceof Role) {
                return $role;
            }

            $method = is_numeric($role) ? 'findById' : 'findByName';

            return $this->getRoleClass()->{$method}($role, $this->getDefaultGuardName());
        }, $roles);

        return $query->whereHas('roles', function ($query) use ($roles) {
            $query->where(function ($query) use ($roles) {
                foreach ($roles as $role) {
                    $query->orWhere(config('permission.table_names.roles').'.id', $role->id);
                }
            });
        });
    }

    /**
     * Assign the given role to the model.
     *
     * @param array|string|\Spatie\Permission\Contracts\Role ...$roles
     *
     * @return $this
     */
    public function assignRole($roles, Restrictable $restrictable = null)
    {
        // Role objects, if directly collected, becomes arrays of fields and the flatten() messes with
        // the map function giving every single Role field as parameter for getStoredRole.
        // To avoid this, if a Role is given an empty collection is created and the role is pushed inside.
        // In this way, in case of a Role instance, the object is not flattened,
        // but for arrays, collections and string everything works as expected.
        $roles = (($roles instanceof Role) ? collect()->push($roles) : collect($roles))
            ->flatten()
            ->map(function ($role) {
                if (empty($role)) {
                    return false;
                }

                return $this->getStoredRole($role);
            })
            ->filter(function ($role) {
                return $role instanceof Role;
            })
            ->each(function ($role) {
                $this->ensureModelSharesGuard($role);
            })
            ->map->id
            ->all();

        $model = $this->getModel();

        if ($model->exists) {
            if (! is_null($restrictable)) {
                $roles = collect($roles)->map(function ($role) use ($restrictable) {
                    return [
                        $role => [
                            'restrictable_id' => $restrictable->getRestrictableId(),
                            'restrictable_type' => $restrictable->getRestrictableTable(),
                        ]
                    ];
                })->all();
            }

            $this->roles()->sync($roles, false);
        } else {
            $class = \get_class($model);

            $class::saved(function ($model) use ($roles, $restrictable) {
                $model->roles()->attach($roles, is_null($restrictable) ? [] : [
                    'restrictable_id' => $restrictable->getRestrictableId(),
                    'restrictable_type' => $restrictable->getRestrictableTable(),
                ], false);
            });
        }

        $this->forgetCachedPermissions();

        return $this;
    }

    /**
     * Revoke the given role from the model.
     *
     * @param string|\Spatie\Permission\Contracts\Role $role
     */
    public function removeRole($role, Restrictable $restrictable = null)
    {
        $this->roles($restrictable)->detach($this->getStoredRole($role));
    }

    /**
     * Remove all current roles and set the given ones.
     *
     * @param array|\Spatie\Permission\Contracts\Role|string ...$roles
     *
     * @return $this
     */
    public function syncRoles($roles, Restrictable $restrictable = null)
    {
        $this->roles($restrictable)->detach();

        return $this->assignRole($roles, $restrictable);
    }

    /**
     * Determine if the model has (one of) the given role(s).
     *
     * @param string|array|\Spatie\Permission\Contracts\Role|\Illuminate\Support\Collection $roles
     *
     * @return bool
     */
    public function hasRole($roles, Restrictable $restrictable = null): bool
    {
        // Needed to preserve the caching mechanism at least for the not scoped roles
        $roleCachedRelation = (is_null($restrictable) ? $this->roles : $this->roles($restrictable)->get());

        if (is_string($roles) && false !== strpos($roles, '|')) {
            $roles = $this->convertPipeToArray($roles);
        }

        if (is_string($roles)) {
            return $roleCachedRelation->contains('name', $roles);
        }

        if ($roles instanceof Role) {
            return $roleCachedRelation->contains('id', $roles->id);
        }

        if (is_array($roles)) {
            foreach ($roles as $role) {
                if ($this->hasRole($role, $restrictable)) {
                    return true;
                }
            }

            return false;
        }

        return $roles->intersect($roleCachedRelation)->isNotEmpty();
    }

    /**
     * Determine if the model has any of the given role(s).
     *
     * @param string|array|\Spatie\Permission\Contracts\Role|\Illuminate\Support\Collection $roles
     *
     * @return bool
     */
    public function hasAnyRole($roles, Restrictable $restrictable = null): bool
    {
        return $this->hasRole($roles, $restrictable);
    }

    /**
     * Determine if the model has all of the given role(s).
     *
     * @param string|\Spatie\Permission\Contracts\Role|\Illuminate\Support\Collection $roles
     *
     * @return bool
     */
    public function hasAllRoles($roles): bool
    {
        // Needed to preserve the caching mechanism at least for the not scoped roles
        $roleCachedRelation = (is_null($restrictable) ? $this->roles : $this->roles($restrictable)->get());

        if (is_string($roles) && false !== strpos($roles, '|')) {
            $roles = $this->convertPipeToArray($roles);
        }

        if (is_string($roles)) {
            return $roleCachedRelation->contains('name', $roles);
        }

        if ($roles instanceof Role) {
            return $roleCachedRelation->contains('id', $roles->id);
        }

        $roles = collect()->make($roles)->map(function ($role) {
            return $role instanceof Role ? $role->name : $role;
        });

        return $roles->intersect($roleCachedRelation->pluck('name')) == $roles;
    }

    /**
     * Return all permissions directly coupled to the model.
     */
    public function getDirectPermissions(Restrictable $restrictable = null): Collection
    {
        // Needed to preserve the caching mechanism at least for the not scoped permissions
        return (is_null($restrictable) ? $this->permissions : $this->permissions($restrictable)->get());
    }

    public function getRoleNames(): Collection
    {
        return $this->roles->pluck('name');
    }

    protected function getStoredRole($role): Role
    {
        $roleClass = $this->getRoleClass();

        if (is_numeric($role)) {
            return $roleClass->findById($role, $this->getDefaultGuardName());
        }

        if (is_string($role)) {
            return $roleClass->findByName($role, $this->getDefaultGuardName());
        }

        return $role;
    }

    protected function convertPipeToArray(string $pipeString)
    {
        $pipeString = trim($pipeString);

        if (strlen($pipeString) <= 2) {
            return $pipeString;
        }

        $quoteCharacter = substr($pipeString, 0, 1);
        $endCharacter = substr($quoteCharacter, -1, 1);

        if ($quoteCharacter !== $endCharacter) {
            return explode('|', $pipeString);
        }

        if (! in_array($quoteCharacter, ["'", '"'])) {
            return explode('|', $pipeString);
        }

        return explode('|', trim($pipeString, $quoteCharacter));
    }
}
