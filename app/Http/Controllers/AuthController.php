<?php

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use App\Helpers\ApiResponse;
use App\Mail\SendVerificationCode;
use Illuminate\Support\Facades\Mail;
use Laravel\Sanctum\PersonalAccessToken;

class AuthController extends Controller
{
    // Register new user
    public function register(Request $request)
    {
        $request->validate([
            'name'     => ['required', 'string', 'max:255'],
            'email'    => ['required', 'string', 'email', 'max:255', 'unique:users'],
            'password' => ['required', 'string', 'min:8'],
        ]);

        $user = User::create([
            'name'     => $request->name,
            'email'    => $request->email,
            'password' => Hash::make($request->password),
        ]);

        // Send verification code
        $this->sendVerificationCode($user);

        // Delete old tokens and create a new one
        $user->tokens()->delete();
        $token = $user->createToken('auth_token')->plainTextToken;

        return ApiResponse::success([
            'user' => $user,
            'access_token' => $token,
            'token_type' => 'Bearer',
        ], 'User registered successfully. Please verify your email with the code sent.', 201);
    }

    // Send OTP code
    protected function sendVerificationCode(User $user)
    {
        $code = rand(100000, 999999);
        $user->verification_code = $code;
        $user->verification_expires_at = now()->addMinutes(15);
        $user->save();

        Mail::to($user->email)->send(new SendVerificationCode($code));
    }

    // Verify code via token in header
    public function verifyCode(Request $request)
    {
        $request->validate(['code' => ['required']]);

        $token = $request->bearerToken();
        if (!$token) {
            return ApiResponse::error('Token not provided', 401);
        }

        $user = PersonalAccessToken::findToken($token)?->tokenable;
        if (!$user) {
            return ApiResponse::error('Invalid token', 401);
        }

        if ((string)$user->verification_code !== (string)$request->code) {
            return ApiResponse::error('Invalid code', 400);
        }

        if ($user->verification_expires_at->isPast()) {
            return ApiResponse::error('Code expired', 400);
        }

        // Verify email
        $user->email_verified_at = now();
        $user->verification_code = null;
        $user->verification_expires_at = null;
        $user->save();

        // Delete all old tokens and create a new one
        $user->tokens()->delete();
        $token = $user->createToken('auth_token')->plainTextToken;

        return ApiResponse::success([
            'user' => $user,
            'access_token' => $token,
            'token_type' => 'Bearer',
        ], 'Email verified successfully');
    }

    // Login user
    public function login(Request $request)
    {
        $request->validate([
            'email'    => ['required', 'email'],
            'password' => ['required'],
        ]);

        $user = User::where('email', $request->email)->first();
        if (!$user || !Hash::check($request->password, $user->password)) {
            return ApiResponse::error('Invalid credentials', 401);
        }

        // Delete old tokens and create new token
        $user->tokens()->delete();
        $token = $user->createToken('auth_token')->plainTextToken;

        // If email not verified, send verification code
        if (!$user->hasVerifiedEmail()) {
            $this->sendVerificationCode($user);
            return ApiResponse::success([
                'user' => $user,
                'access_token' => $token,
                'token_type' => 'Bearer',
            ], 'Please verify your email first. Verification code sent.');
        }

        // Email verified, return token and user
        return ApiResponse::success([
            'user' => $user,
            'access_token' => $token,
            'token_type' => 'Bearer',
        ], 'Login successful');
    }

    // Current user info (requires token)
    public function me(Request $request)
    {
        return ApiResponse::success($request->user(), 'Current user fetched');
    }

    // Logout
    public function logout(Request $request)
    {
        $request->user()->currentAccessToken()->delete();
        return ApiResponse::success(null, 'Logged out successfully');
    }

    // Check email verification status (requires token)
    public function checkEmailVerified(Request $request)
    {
        $user = $request->user();
        return ApiResponse::success([
            'verified' => $user->hasVerifiedEmail(),
        ], 'Email verification status fetched');
    }
}
