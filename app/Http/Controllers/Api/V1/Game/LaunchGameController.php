<?php

namespace App\Http\Controllers\Api\V1\Game;

use App\Enums\SeamlessWalletCode;
use App\Http\Controllers\Controller;
use App\Models\GameList;
use App\Models\User;
use App\Services\ApiResponseService;
use Carbon\Carbon;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Str; // Make sure to use Http facade for making requests

class LaunchGameController extends Controller
{
    private const LANGUAGE_CODE = 0; // Keeping as 0 as per your provided code

    private const PLATFORM_WEB = 'WEB';

    private const PLATFORM_DESKTOP = 'DESKTOP';

    private const PLATFORM_MOBILE = 'MOBILE';

    // Removed generateGameToken and verifyGameToken as they are no longer needed
    // for the 'password' field based on provider's clarification.
    // However, if your application uses them for other internal purposes, keep them.

    /**
     * Handles the game launch request.
     * This method validates the incoming request, authenticates the user,
     * generates a signature, constructs a payload, and makes an HTTP call
     * to an external game provider's launch API.
     *
     * @param  Request  $request  The incoming HTTP request containing game launch details.
     * @return \Illuminate\Http\JsonResponse
     */
    public function launchGame(Request $request)
    {
        Log::info('Launch Game API Request Started', [
            'request' => $request->all(),
            'ip' => $request->ip(),
            'user_agent' => $request->userAgent(),
            'timestamp' => now()->toISOString()
        ]);

        $user = Auth::user();
        if (! $user) {
            Log::warning('Unauthenticated user attempting game launch.', [
                'ip' => $request->ip(),
                'user_agent' => $request->userAgent(),
                'timestamp' => now()->toISOString()
            ]);

            return ApiResponseService::error(
                SeamlessWalletCode::MemberNotExist,
                'Authentication required. Please log in.'
            );
        }

        Log::info('User authenticated for game launch', [
            'user_id' => $user->id,
            'user_name' => $user->user_name,
            'user_email' => $user->email,
            'timestamp' => now()->toISOString()
        ]);

        try {
            Log::info('Starting request validation', [
                'game_code' => $request->input('game_code'),
                'product_code' => $request->input('product_code'),
                'game_type' => $request->input('game_type'),
                'timestamp' => now()->toISOString()
            ]);

            $validatedData = $request->validate([
                'game_code' => 'required|string',
                'product_code' => 'required|integer',
                'game_type' => 'required|string',
            ]);

            Log::info('Request validation successful', [
                'validated_data' => $validatedData,
                'timestamp' => now()->toISOString()
            ]);

            $currencyMap = [
                1007 => 'MMK2', 1221 => 'MMK2', 1040 => 'MMK2',
                1046 => 'MMK2', 1004 => 'MMK2',
            ];

            // Use mapped currency or fall back to MMK if config currency is invalid
            $configCurrency = config('seamless_key.api_currency');
            $apiCurrency = $currencyMap[$validatedData['product_code']] ?? 
                          (in_array($configCurrency, ['IDR', 'MMK2', 'MMK3']) ? $configCurrency : 'MMK');

            Log::info('Currency mapping determined', [
                'product_code' => $validatedData['product_code'],
                'config_currency' => $configCurrency,
                'mapped_currency' => $currencyMap[$validatedData['product_code']] ?? 'not_found',
                'final_currency' => $apiCurrency,
                'timestamp' => now()->toISOString()
            ]);

        } catch (\Illuminate\Validation\ValidationException $e) {
            Log::warning('Launch Game API Validation Failed', [
                'errors' => $e->errors(),
                'request_data' => $request->all(),
                'user_id' => $user->id,
                'timestamp' => now()->toISOString()
            ]);

            return ApiResponseService::error(
                SeamlessWalletCode::InternalServerError,
                'Validation failed',
                $e->errors()
            );
        }

        // Get or generate password
        Log::info('Checking game provider password for user', [
            'user_id' => $user->id,
            'timestamp' => now()->toISOString()
        ]);

        $gameProviderPassword = $user->getGameProviderPassword();
        if (! $gameProviderPassword) {
            Log::info('No existing game provider password found, generating new one', [
                'user_id' => $user->id,
                'timestamp' => now()->toISOString()
            ]);

            $gameProviderPassword = Str::random(50);
            $user->setGameProviderPassword($gameProviderPassword);
            
            Log::info('Generated and stored new game provider password for user', [
                'user_id' => $user->id,
                'password_length' => strlen($gameProviderPassword),
                'timestamp' => now()->toISOString()
            ]);
        } else {
            Log::info('Using existing game provider password for user', [
                'user_id' => $user->id,
                'password_length' => strlen($gameProviderPassword),
                'timestamp' => now()->toISOString()
            ]);
        }

        Log::info('Loading configuration values', [
            'timestamp' => now()->toISOString()
        ]);

        $agentCode = config('seamless_key.agent_code');
        $secretKey = config('seamless_key.secret_key');
        $apiUrl = config('seamless_key.api_url').'/api/operators/launch-game';
        $operatorLobbyUrl = 'https://pp29.site';
        $requestTime = now('Asia/Shanghai')->timestamp;

        Log::info('Configuration loaded', [
            'agent_code' => $agentCode,
            'api_url' => $apiUrl,
            'operator_lobby_url' => $operatorLobbyUrl,
            'request_time' => $requestTime,
            'timezone' => 'Asia/Shanghai',
            'timestamp' => now()->toISOString()
        ]);

        $generatedSignature = md5($requestTime.$secretKey.'launchgame'.$agentCode);
        
        Log::info('Signature generated', [
            'request_time' => $requestTime,
            'signature' => $generatedSignature,
            'signature_length' => strlen($generatedSignature),
            'timestamp' => now()->toISOString()
        ]);

        $payload = [
            'operator_code' => $agentCode,
            'member_account' => $user->user_name,
            'password' => $gameProviderPassword,
            'nickname' => $request->input('nickname') ?? $user->name,
            'currency' => $apiCurrency,
            'game_code' => $validatedData['game_code'],
            'product_code' => $validatedData['product_code'],
            'game_type' => $validatedData['game_type'],
            'language_code' => self::LANGUAGE_CODE,
            'ip' => $request->ip(),
            'platform' => self::PLATFORM_WEB,
            'sign' => $generatedSignature,
            'request_time' => $requestTime,
            'operator_lobby_url' => $operatorLobbyUrl,
        ];

        Log::info('Payload constructed successfully', [
            'payload_keys' => array_keys($payload),
            'payload_size' => strlen(json_encode($payload)),
            'timestamp' => now()->toISOString()
        ]);

        Log::info('Sending Launch Game Request to Provider', [
            'url' => $apiUrl,
            'payload' => $payload,
            'user_id' => $user->id,
            'timestamp' => now()->toISOString()
        ]);

        try {
            Log::info('Making HTTP request to provider API', [
                'url' => $apiUrl,
                'method' => 'POST',
                'headers' => [
                    'Content-Type' => 'application/json',
                    'Accept' => 'application/json'
                ],
                'timestamp' => now()->toISOString()
            ]);

            $response = Http::withHeaders([
                'Content-Type' => 'application/json',
                'Accept' => 'application/json',
            ])->post($apiUrl, $payload);

            Log::info('Provider API response received', [
                'status_code' => $response->status(),
                'response_headers' => $response->headers(),
                'response_size' => strlen($response->body()),
                'timestamp' => now()->toISOString()
            ]);

            $responseData = $response->json();

            Log::info('Provider API response parsed', [
                'response_data' => $responseData,
                'has_url' => !empty($responseData['url']),
                'has_content' => !empty($responseData['content']),
                'response_code' => $responseData['code'] ?? 'not_set',
                'timestamp' => now()->toISOString()
            ]);

            // If response fails or has error code, log and return error
            if (! $response->successful() || empty($responseData['url']) && empty($responseData['content'])) {
                Log::error('Provider Launch Game Failed', [
                    'status' => $response->status(),
                    'body' => $response->body(),
                    'response_data' => $responseData,
                    'payload' => $payload,
                    'user_id' => $user->id,
                    'timestamp' => now()->toISOString()
                ]);

                return response()->json([
                    'code' => $responseData['code'] ?? 500,
                    'message' => $responseData['message'] ?? 'Launch failed',
                ], 500);
            }

            // If MMK2 provider, return `content` if present (e.g., for PGSoft etc.)
            if ($apiCurrency === 'MMK2') {
                Log::info('Returning MMK2 provider response', [
                    'currency' => $apiCurrency,
                    'response_code' => $responseData['code'] ?? SeamlessWalletCode::Success->value,
                    'has_url' => !empty($responseData['url']),
                    'has_content' => !empty($responseData['content']),
                    'user_id' => $user->id,
                    'timestamp' => now()->toISOString()
                ]);

                return response()->json([
                    'code' => $responseData['code'] ?? SeamlessWalletCode::Success->value,
                    'message' => $responseData['message'] ?? 'Game launched successfully',
                    'url' => $responseData['url'] ?? '',
                    'content' => $responseData['content'] ?? '',
                ]);
            }

            // Otherwise, return just the URL
            Log::info('Returning standard provider response', [
                'currency' => $apiCurrency,
                'response_code' => 200,
                'has_url' => !empty($responseData['url']),
                'user_id' => $user->id,
                'timestamp' => now()->toISOString()
            ]);

            Log::info('Game launch completed successfully', [
                'user_id' => $user->id,
                'currency' => $apiCurrency,
                'game_code' => $validatedData['game_code'],
                'product_code' => $validatedData['product_code'],
                'timestamp' => now()->toISOString()
            ]);

            return response()->json([
                'code' => 200,
                'message' => 'Game launched successfully',
                'url' => $responseData['url'],
            ]);
        } catch (\Throwable $e) {
            Log::error('Unexpected error during provider API call', [
                'exception' => $e->getMessage(),
                'exception_class' => get_class($e),
                'exception_code' => $e->getCode(),
                'exception_file' => $e->getFile(),
                'exception_line' => $e->getLine(),
                'trace' => $e->getTraceAsString(),
                'request_payload' => $payload,
                'user_id' => $user->id,
                'timestamp' => now()->toISOString()
            ]);

            return response()->json([
                'code' => 500,
                'message' => 'Unexpected error: '.$e->getMessage(),
            ], 500);
        }
    }

    //      public function launchGame(Request $request)
    // {
    //     Log::info('Launch Game API Request', ['request' => $request->all()]);

    //     $user = Auth::user();
    //     if (! $user) {
    //         Log::warning('Unauthenticated user attempting game launch.');
    //         return ApiResponseService::error(
    //             SeamlessWalletCode::MemberNotExist,
    //             'Authentication required. Please log in.'
    //         );
    //     }

    //     try {
    //         $validatedData = $request->validate([
    //             'game_code' => 'required|string',
    //             'product_code' => 'required|integer',
    //             'game_type' => 'required|string',
    //         ]);

    //         $currencyMap = [
    //             1007 => 'MMK2',
    //             1221 => 'MMK2',
    //             1040 => 'MMK2',
    //             1046 => 'MMK2',
    //             1004 => 'MMK2',
    //         ];

    //         $apiCurrency = $currencyMap[$validatedData['product_code']] ?? config('seamless_key.api_currency');

    //     } catch (\Illuminate\Validation\ValidationException $e) {
    //         Log::warning('Launch Game API Validation Failed', ['errors' => $e->errors()]);
    //         return ApiResponseService::error(
    //             SeamlessWalletCode::InternalServerError,
    //             'Validation failed',
    //             $e->errors()
    //         );
    //     }

    //     $gameProviderPassword = $user->getGameProviderPassword();
    //     if (! $gameProviderPassword) {
    //         $gameProviderPassword = Str::random(50);
    //         $user->setGameProviderPassword($gameProviderPassword);
    //         Log::info('Generated and stored new game provider password for user', ['user_id' => $user->id]);
    //     }

    //     $agentCode = config('seamless_key.agent_code');
    //     $secretKey = config('seamless_key.secret_key');
    //     $apiUrl = config('seamless_key.api_url') . '/api/operators/launch-game';
    //     $operatorLobbyUrl = 'https://pp29.site';
    //     $requestTime = now('Asia/Shanghai')->timestamp;
    //     $generatedSignature = md5($requestTime . $secretKey . 'launchgame' . $agentCode);

    //     $payload = [
    //         'operator_code' => $agentCode,
    //         'member_account' => $user->user_name,
    //         'password' => $gameProviderPassword,
    //         'nickname' => $request->input('nickname') ?? $user->name,
    //         'currency' => $apiCurrency,
    //         'game_code' => $validatedData['game_code'],
    //         'product_code' => $validatedData['product_code'],
    //         'game_type' => $validatedData['game_type'],
    //         'language_code' => self::LANGUAGE_CODE,
    //         'ip' => $request->ip(),
    //         'platform' => self::PLATFORM_WEB,
    //         'sign' => $generatedSignature,
    //         'request_time' => $requestTime,
    //         'operator_lobby_url' => $operatorLobbyUrl,
    //     ];

    //     Log::info('Sending Launch Game Request to Provider', ['url' => $apiUrl, 'payload' => $payload]);

    //     try {
    //         $response = Http::withHeaders([
    //             'Content-Type' => 'application/json',
    //             'Accept' => 'application/json',
    //         ])->post($apiUrl, $payload);

    //         $responseData = $response->json();

    //         // if($currencyMap[$validatedData['product_code']] == 'MMK2'){
    //         //     return response()->json([
    //         //         'code' => $responseData['code'] ?? SeamlessWalletCode::InternalServerError->value,
    //         //         'message' => $responseData['message'] ?? 'Game launched successfully',
    //         //         'url' => $responseData['url'] ?? '',
    //         //         'content' => $responseData['content'] ?? '',
    //         //     ]);
    //         // }

    //         if ($response->successful() && !empty($responseData['url'])) {
    //             return response()->json([
    //                 'code' => 200,
    //                 'message' => 'Game launched successfully',
    //                 'url' => $responseData['url'],
    //             ]);
    //         }

    //         Log::error('Provider Launch Game Failed', [
    //             'status' => $response->status(),
    //             'body' => $response->body(),
    //             'payload' => $payload,
    //         ]);

    //         return response()->json([
    //             'code' => $responseData['code'] ?? 500,
    //             'message' => $responseData['message'] ?? 'Launch failed',
    //         ], 500);

    //     } catch (\Throwable $e) {
    //         Log::error('Unexpected error during provider API call', [
    //             'exception' => $e->getMessage(),
    //             'trace' => $e->getTraceAsString(),
    //             'request_payload' => $payload,
    //         ]);

    //         return response()->json([
    //             'code' => 500,
    //             'message' => 'Unexpected error: ' . $e->getMessage(),
    //         ], 500);
    //     }
    // }

    // public function launchGame(Request $request)
    // {
    //     Log::info('Launch Game API Request', ['request' => $request->all()]);

    //     $user = Auth::user();
    //     if (! $user) {
    //         Log::warning('Unauthenticated user attempting game launch.');

    //         return ApiResponseService::error(
    //             SeamlessWalletCode::MemberNotExist,
    //             'Authentication required. Please log in.'
    //         );
    //     }

    //     try {
    //         $validatedData = $request->validate([
    //             'game_code' => 'required|string',
    //             'product_code' => 'required|integer',
    //             'game_type' => 'required|string',
    //         ]);
    //         // Define custom currency mapping for special providers
    //         $currencyMap = [
    //             1007 => 'MMK2',   // PG Soft
    //             1221 => 'MMK2',
    //             1040 => 'MMK2',
    //             1046 => 'MMK2',
    //             1004 => 'MMK2',
    //         ];

    //         // Use mapped currency or fall back to default config
    //         $apiCurrency = $currencyMap[$validatedData['product_code']] ?? config('seamless_key.api_currency');

    //     } catch (\Illuminate\Validation\ValidationException $e) {
    //         Log::warning('Launch Game API Validation Failed', ['errors' => $e->errors()]);

    //         return ApiResponseService::error(
    //             SeamlessWalletCode::InternalServerError,
    //             'Validation failed',
    //             $e->errors()
    //         );
    //     }

    //     // --- NEW LOGIC FOR GAME PROVIDER PASSWORD ---
    //     $gameProviderPassword = $user->getGameProviderPassword();

    //     // If the user doesn't have a game provider password yet, generate and store one
    //     if (! $gameProviderPassword) {
    //         // Generate a strong, unique, and consistent password for this player for the game provider
    //         // The provider states "The same password will always need to be used for the exact player after creation."
    //         $gameProviderPassword = Str::random(50); // Generates a 32-character random string
    //         $user->setGameProviderPassword($gameProviderPassword); // Saves and encrypts in DB
    //         Log::info('Generated and stored new game provider password for user', ['user_id' => $user->id]);
    //     }
    //     // --- END NEW LOGIC ---

    //     $agentCode = config('seamless_key.agent_code');
    //     $secretKey = config('seamless_key.secret_key');
    //     $apiUrl = config('seamless_key.api_url').'/api/operators/launch-game';
    //     //$apiCurrency = config('seamless_key.api_currency');
    //     $operatorLobbyUrl = 'https://amk-movies-five.vercel.app';

    //     $nowGmt8 = now('Asia/Shanghai');
    //     $requestTime = $nowGmt8->timestamp;

    //     $generatedSignature = md5(
    //         $requestTime.$secretKey.'launchgame'.$agentCode
    //     );

    //     // $game_code = 'null';

    //     $payload = [
    //         'operator_code' => $agentCode,
    //         'member_account' => $user->user_name,
    //         'password' => $gameProviderPassword, // <-- Use the consistent password stored in your DB
    //         'nickname' => $request->input('nickname') ?? $user->name,
    //         'currency' => $apiCurrency,
    //         'game_code' => $validatedData['game_code'],
    //         'product_code' => $validatedData['product_code'],
    //         'game_type' => $validatedData['game_type'],
    //         'language_code' => self::LANGUAGE_CODE,
    //         'ip' => $request->ip(),
    //         'platform' => self::PLATFORM_WEB,
    //         'sign' => $generatedSignature,
    //         'request_time' => $requestTime,
    //         'operator_lobby_url' => $operatorLobbyUrl,
    //     ];

    //     Log::info('Sending Launch Game Request to Provider', ['url' => $apiUrl, 'payload' => $payload]);

    //     try {
    //         $response = Http::withHeaders([
    //             'Content-Type' => 'application/json',
    //             'Accept' => 'application/json',
    //         ])->post($apiUrl, $payload);

    //         if ($response->successful()) {
    //             $responseData = $response->json();
    //             // Log::info('Provider Launch Game API Response', ['response' => $responseData]);

    //             return response()->json([
    //                 'code' => $responseData['code'] ?? SeamlessWalletCode::InternalServerError->value,
    //                 'message' => $responseData['message'] ?? 'Game launched successfully',
    //                 'url' => $responseData['url'] ?? '',
    //                 'content' => $responseData['content'] ?? '',
    //             ]);
    //         }

    //         Log::error('Provider Launch Game API Request Failed', [
    //             'status' => $response->status(),
    //             'body' => $response->body(),
    //             'request_payload' => $payload,
    //         ]);

    //         return response()->json(
    //             ['code' => $response->status(), 'message' => 'Provider API request failed', 'url' => '', 'content' => $response->body()],
    //             $response->status()
    //         );
    //     } catch (\Throwable $e) {
    //         Log::error('Unexpected error during provider API call', [
    //             'exception' => $e->getMessage(),
    //             'trace' => $e->getTraceAsString(),
    //             'request_payload' => $payload,
    //         ]);

    //         return response()->json(
    //             ['code' => 500, 'message' => 'Unexpected error', 'url' => '', 'content' => $e->getMessage()],
    //             500
    //         );
    //     }
    // }
}
