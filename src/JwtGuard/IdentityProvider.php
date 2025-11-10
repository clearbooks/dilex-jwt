<?php

declare(strict_types=1);

namespace Clearbooks\Dilex\JwtGuard;

interface IdentityProvider
{
    public function getUserId(): mixed;

    public function getGroupId(): mixed;

    public function getIsAdmin(): bool;

    public function getSegments(): array;
}
