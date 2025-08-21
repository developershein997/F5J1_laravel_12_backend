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
        Schema::create('three_d_bet_slips', function (Blueprint $table) {
            $table->id();
            $table->string('slip_no')->unique();
            $table->unsignedBigInteger('user_id');
            $table->string('player_name')->nullable();
            $table->unsignedBigInteger('agent_id')->nullable();
            $table->decimal('total_bet_amount', 12, 2);
            $table->string('draw_session'); // e.g., '2024-01-16', '2024-02-01', etc.
            $table->enum('status', ['pending', 'completed', 'cancelled'])->default('pending');
            $table->date('game_date');
            $table->time('game_time')->nullable();
            $table->decimal('before_balance', 12, 2);
            $table->decimal('after_balance', 12, 2);
            $table->timestamps();

            $table->foreign('user_id')->references('id')->on('users')->onDelete('cascade');
            $table->foreign('agent_id')->references('id')->on('users')->onDelete('set null');
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('three_d_bet_slips');
    }
};
