<?php
namespace Clearbooks\Dilex;
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

    /**
     * Authorise this request
     * @param Request $request
     * @return null|JsonResponse
     */
    public function execute( Request $request )
    {

        if( !$this->authoriser->isAuthorised( $request ) ) {
            return new JsonResponse('{"error": "Invalid token"}', 403);
        }
        return null;
    }
}