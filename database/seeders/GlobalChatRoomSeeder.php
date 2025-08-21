<?php

namespace Database\Seeders;

use App\Models\ChatRoom;
use Illuminate\Database\Seeder;

class GlobalChatRoomSeeder extends Seeder
{
    /**
     * Run the database seeds.
     */
    public function run(): void
    {
        // Create global chat room
        ChatRoom::firstOrCreate(
            ['is_global' => true],
            [
                'name' => 'Global Chat',
                'description' => 'Global chat room for all players',
                'is_active' => true,
                'is_global' => true,
                'max_participants' => null
            ]
        );

        $this->command->info('Global chat room created successfully!');
    }
}
