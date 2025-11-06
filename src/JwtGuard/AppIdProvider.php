<?php

declare(strict_types=1);

namespace Clearbooks\Dilex\JwtGuard;

interface AppIdProvider
{
    public function getAppIds(): array;
}
