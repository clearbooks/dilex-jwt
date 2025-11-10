<?php

declare(strict_types=1);

namespace Clearbooks\Dilex\JwtGuard;

use Symfony\Component\HttpFoundation\Request;

interface RequestAuthoriser
{
    public function isAuthorised( Request $request ): bool;
}
