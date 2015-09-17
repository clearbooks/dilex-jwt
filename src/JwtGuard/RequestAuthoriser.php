<?php
namespace Clearbooks\Dilex\JwtGuard;
use Symfony\Component\HttpFoundation\Request;
use Emarref\Jwt\Token;

interface RequestAuthoriser
{
    public function isAuthorised( Request $request );
}