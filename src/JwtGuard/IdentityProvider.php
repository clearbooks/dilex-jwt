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

    /**
     * @author Nicky Santamaria <nick.s@clearbooks.co.uk>
     * @return int|null
     */
    public function getDbId();
}
