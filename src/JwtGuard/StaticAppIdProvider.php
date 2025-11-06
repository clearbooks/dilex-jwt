<?php

declare(strict_types=1);

namespace Clearbooks\Dilex\JwtGuard;

class StaticAppIdProvider implements AppIdProvider
{
    /**
     * @param string[] $appIds
     */
    public function __construct( private array $appIds )
    {}

    #[\Override]
    public function getAppIds(): array
    {
        return $this->appIds;
    }
}
