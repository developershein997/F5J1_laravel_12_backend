<?php

namespace Database\Seeders;

use Illuminate\Database\Console\Seeds\WithoutModelEvents;
use Illuminate\Database\Seeder;
use Illuminate\Support\Facades\DB;

class ThreeDCloseDigitSeeder extends Seeder
{
    /**
     * Run the database seeds.
     */
    public function run(): void
    {
        // Clear existing data
        DB::table('three_d_close_digits')->delete();

        // Insert 3-digit close digits from 000 to 999
        for ($i = 0; $i <= 999; $i++) {
            DB::table('three_d_close_digits')->insert([
                'close_digit' => str_pad($i, 3, '0', STR_PAD_LEFT), // Format as 000, 001, 002, ..., 999
                'status' => true, // Default status is true (open for betting)
                'created_at' => now(),
                'updated_at' => now(),
            ]);
        }

        $this->command->info('ThreeD close digits (000-999) seeded successfully!');
    }
}
