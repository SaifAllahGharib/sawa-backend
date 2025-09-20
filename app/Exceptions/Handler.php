<?php

namespace App\Exceptions;

use Illuminate\Foundation\Exceptions\Handler as ExceptionHandler;
use Throwable;
use Illuminate\Validation\ValidationException;
use Symfony\Component\HttpKernel\Exception\NotFoundHttpException;
use Symfony\Component\HttpKernel\Exception\MethodNotAllowedHttpException;

class Handler extends ExceptionHandler
{
    /**
     * A list of the exception types that are not reported.
     *
     * @var array<int, class-string<Throwable>>
     */
    protected $dontReport = [
        //
    ];

    /**
     * A list of the inputs that are never flashed for validation exceptions.
     *
     * @var array<int, string>
     */
    protected $dontFlash = [
        'current_password',
        'password',
        'password_confirmation',
    ];

    /**
     * Register the exception handling callbacks for the application.
     */
    public function register(): void
    {
        $this->renderable(function (Throwable $e, $request) {
            if ($request->expectsJson()) {
                // Validation Errors
                if ($e instanceof ValidationException) {
                    return response()->json([
                        'status'  => 'error',
                        'message' => 'Validation failed',
                        'errors'  => $e->errors(),
                    ], 422);
                }

                // Route not found
                if ($e instanceof NotFoundHttpException) {
                    return response()->json([
                        'status'  => 'error',
                        'message' => 'Route not found',
                    ], 404);
                }

                // Method not allowed
                if ($e instanceof MethodNotAllowedHttpException) {
                    return response()->json([
                        'status'  => 'error',
                        'message' => 'Method not allowed',
                    ], 405);
                }

                // Any other error
                return response()->json([
                    'status'  => 'error',
                    'message' => $e->getMessage() ?: 'Something went wrong',
                ], 500);
            }
        });
    }
}
