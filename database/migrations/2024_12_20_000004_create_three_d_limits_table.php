<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    /**
     * Run the migrations.
     */
    public function up(): void
    {
        Schema::create('three_d_limits', function (Blueprint $table) {
            $table->id();
            $table->decimal('min_bet_amount', 10, 2)->default(1.00);
            $table->decimal('max_bet_amount', 10, 2)->default(10000.00);
            $table->decimal('max_total_bet', 10, 2)->default(100000.00);
            $table->decimal('payout_multiplier', 10, 2)->default(800.00); // 800x for 3D
            $table->boolean('is_active')->default(true);
            $table->text('description')->nullable();
            $table->timestamps();
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('three_d_limits');
    }
};
