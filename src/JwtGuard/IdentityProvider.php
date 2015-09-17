<?php
namespace Clearbooks\Dilex\JwtGuard;

interface IdentityProvider
{
    public function getUserId();

    public function getGroupId();
}