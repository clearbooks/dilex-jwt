<?php

declare(strict_types=1);

namespace Clearbooks\Dilex;

use Clearbooks\Dilex\JwtGuard\NoJwtRequired;
use Clearbooks\Dilex\JwtGuard\RequestAuthoriser;
use Closure;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

use function is_array;
use function is_string;

class JwtGuard implements Middleware
{
    public function __construct( private readonly RequestAuthoriser $authoriser )
    {}

    private function getControllerClass( Request $request ): string|Closure|null
    {
        $controllerAttribute = $request->attributes->get( "_controller" );
        if ( is_array( $controllerAttribute ) ) {
            return $controllerAttribute[0];
        }

        return $controllerAttribute;
    }

    #[\Override]
    public function execute( Request $request ): ?JsonResponse
    {
        $controllerClass = $this->getControllerClass( $request );
        if( !($this->isJwtRequired($controllerClass))) {
            return null;
        }

        if( !$this->authoriser->isAuthorised( $request ) ) {
            return new JsonResponse( ['error' => 'Invalid token'], Response::HTTP_FORBIDDEN );
        }

        return null;
    }

    private function isJwtRequired(string|Closure|null $controllerClass): bool
    {
        if (!is_string($controllerClass)) {
            return true;
        }

        $reflection = new \ReflectionClass($controllerClass);

        return !$reflection->implementsInterface(NoJwtRequired::class);
    }
}
