<?php

namespace App\Http\Controllers\Api\V1\Player;

use App\Http\Controllers\Controller;
use App\Models\User;
use App\Enums\UserType;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Validator;
use Illuminate\Support\Str;
use Illuminate\Support\Facades\Log;

class AutoPlayerCreateController extends Controller
{

    private const PLAYER_ROLE = 5;

    public function register(Request $request)
    {
        // Validate the request
        $validator = Validator::make($request->all(), [
            'name' => 'required|string|max:255',
            'user_name' => 'required|string|max:255|unique:users',
            'phone' => 'nullable|string|max:255',
            'password' => 'required|string|min:6|confirmed',
            'agent_id' => 'nullable|exists:users,id',
            //'status' => 'required|integer|in:1',
            'is_changed_password' => 'required|integer|in:1',
            'type' => 'required|integer|in:40',
            'referral_code' => 'nullable|string|max:255',
        ]);

        if ($validator->fails()) {
            return response()->json([
                'status' => 'error',
                'message' => 'Validation failed',
                'errors' => $validator->errors()
            ], 422);
        }


        // get referral_code

        $agent_referral_code = 'AGENTGiW3Sy';

        $agent = User::where('referral_code', $agent_referral_code)->first();

        Log::info([
            'agent_id' => $agent->id,
            'agent_referral_code' => $agent_referral_code,
            'agent_name' => $agent->name,
            'agent_user_name' => $agent->user_name,
        ]);

        if (!$agent) {
            return response()->json([
                'status' => 'error',
                'message' => 'Agent not found',
            ], 404);
        }
        try {
            // Create the guest user
            $user = User::create([
                'name' => $request->name,
                'user_name' => $request->user_name,
                'phone' => $request->phone,
                'password' => Hash::make($request->password),
                'agent_id' => $agent->id,
                'status' => 1,
                'is_changed_password' => $request->is_changed_password,
                'type' => $request->type,
                'referral_code' => $request->referral_code,
            ]);

            $user->roles()->sync(self::PLAYER_ROLE);


            // Generate token
            $token = $user->createToken($user->user_name)->plainTextToken;

            return response()->json([
                'status' => 'success',
                'message' => 'Guest account created successfully',
                'data' => [
                    'user' => $user,
                    'token' => $token
                ]
            ], 201);

        } catch (\Exception $e) {
            return response()->json([
                'status' => 'error',
                'message' => 'Failed to create guest account',
                'error' => $e->getMessage()
            ], 500);
        }
    }
    // public function AutoCreatePlayerStore(Request $request)
    // {
    //     $data = $request->validate([
    //         'agent_id' => ['required', 'integer', 'exists:users,id'],
    //         'count' => ['nullable', 'integer', 'min:1', 'max:200'], // limit to prevent abuse
    //         // optional default username prefix
    //         'prefix' => ['nullable', 'string', 'max:30'],
    //     ]);

    //     $count = $data['count'] ?? 1;
    //     $agent = User::findOrFail($data['agent_id']);

    //     // Optional: authorization check (only allow agent owner etc.)
    //     // if (!auth()->user()->canCreateFor($agent)) { abort(403); }

    //     $created = [];

    //     DB::beginTransaction();
    //     try {
    //         for ($i = 0; $i < $count; $i++) {
    //             // Generate a unique username
    //             $username = $this->generateUniqueUsername($agent, $data['prefix'] ?? null);

    //             // Generate a random password and hash it
    //             $plainPassword = Str::random(8); // adjust length
    //             $passwordHash = Hash::make($plainPassword);

    //             $user = User::create([
    //                 'user_name' => $username,
    //                 'name' => null,
    //                 'phone' => null,
    //                 'email' => null,
    //                 'password' => $passwordHash,
    //                 'profile' => null,
    //                 'max_score' => 0,
    //                 'status' => 1,
    //                 'is_changed_password' => 0, // force change on first login maybe
    //                 'agent_id' => $agent->id,
    //                 'payment_type_id' => null,
    //                 'agent_logo' => 'default.png',
    //                 'account_name' => null,
    //                 'account_number' => null,
    //                 'line_id' => null,
    //                 'commission' => 0.00,
    //                 'referral_code' => null,
    //                 'site_name' => null,
    //                 'site_link' => null,
    //                 'type' => (string) UserType::Player->value, // adapt to your storage convention
    //                 'shan_agent_code' => null,
    //                 'shan_agent_name' => null,
    //                 'shan_secret_key' => null,
    //                 'shan_call_back_url' => null,
    //             ]);

    //             $created[] = [
    //                 'id' => $user->id,
    //                 'user_name' => $username,
    //                 'plain_password' => $plainPassword,
    //             ];
    //         }

    //         DB::commit();

    //         return response()->json([
    //             'success' => true,
    //             'message' => 'Players created.',
    //             'created' => $created,
    //         ], 201);
    //     } catch (\Exception $e) {
    //         DB::rollBack();
    //         \Log::error('Auto create players failed: '.$e->getMessage());

    //         return response()->json([
    //             'success' => false,
    //             'message' => 'Failed to create players',
    //         ], 500);
    //     }
    // }

    // protected function generateUniqueUsername(User $agent, ?string $prefix = null): string
    // {
    //     // Build a prefix from agent username or provided prefix
    //     $base = $prefix ? preg_replace('/\s+/', '', $prefix) : ($agent->user_name ?? 'agent'.$agent->id);
    //     $base = strtolower(substr($base, 0, 20)); // limit length

    //     // Try sequential attempts until unique
    //     $attempt = 0;
    //     do {
    //         $suffix = strtoupper(substr(md5(uniqid((string) microtime(true) . $attempt, true)), 0, 5));
    //         // Example username: <base>P<suffix>
    //         $username = $base . 'p' . $suffix;

    //         // Sometimes you might want a numeric sequence like agentID + 6-digit
    //         // $username = $base . sprintf('%06d', random_int(0, 999999));

    //         $attempt++;
    //         // Stop if too many attempts (safety)
    //         if ($attempt > 20) {
    //             // fallback to a UUID piece
    //             $username = $base . 'p' . substr((string) Str::uuid(), 0, 8);
    //             break;
    //         }
    //     } while (User::where('user_name', $username)->exists());

    //     return $username;
    // }
}