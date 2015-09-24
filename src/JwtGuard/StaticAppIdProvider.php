<?php


namespace Clearbooks\Dilex\JwtGuard;


class StaticAppIdProvider implements AppIdProvider
{
    /**
     * @var string[]
     */
    private $appIds;

    /**
     * @param string[] $appIds
     */
    public function __construct( array $appIds )
    {
        $this->appIds = $appIds;
    }

    public function getAppIds()
    {
        return $this->appIds;
    }
}