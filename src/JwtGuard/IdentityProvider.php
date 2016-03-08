<?php
namespace Clearbooks\Dilex\JwtGuard;

interface IdentityProvider
{
    /**
     * @return string
     */
    public function getUserId();

    /**
     * @return string
     */
    public function getGroupId();

    /**
     * @return bool
     */
    public function getIsAdmin();

    /**
     * @return array
     */
    public function getSegments();
}
