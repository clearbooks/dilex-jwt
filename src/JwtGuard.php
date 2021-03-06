<?php
namespace Clearbooks\Dilex;

use Clearbooks\Dilex\JwtGuard\NoJwtRequired;
use Clearbooks\Dilex\JwtGuard\RequestAuthoriser;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;

class JwtGuard implements Middleware
{
    /**
     * @var RequestAuthoriser
     */
    private $authoriser;

    /**
     * JwtGuard constructor.
     * @param RequestAuthoriser $authoriser
     */
    public function __construct( RequestAuthoriser $authoriser )
    {
        $this->authoriser = $authoriser;
    }

    private function getControllerClass( Request $request )
    {
        $controllerAttribute = $request->attributes->get( "_controller" );
        if ( is_array( $controllerAttribute ) ) {
            return $controllerAttribute[0];
        }

        return $controllerAttribute;
    }

    /**
     * Authorise this request
     * @param Request $request
     * @return JsonResponse|null
     */
    public function execute( Request $request )
    {
        $controllerClass = $this->getControllerClass( $request );
        if( !($this->isJwtRequired($controllerClass))) {
            return null;
        }

        if( !$this->authoriser->isAuthorised( $request ) ) {
            return new JsonResponse( ['error' => 'Invalid token'], 403 );
        }
        return null;
    }

    /**
     * @param $controllerClass
     * @return bool
     */
    private function isJwtRequired($controllerClass)
    {
        if ($controllerClass) {
            $reflection = new \ReflectionClass($controllerClass);
            $jwtRequired = !$reflection->implementsInterface(NoJwtRequired::class);
            return $jwtRequired;
        } else {
            $jwtRequired = true;
            return $jwtRequired;
        }
    }
}
