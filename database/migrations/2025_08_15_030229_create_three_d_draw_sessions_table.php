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
        Schema::create('three_d_draw_sessions', function (Blueprint $table) {
            $table->id();
            $table->string('draw_session')->unique(); // e.g., '2024-01-16'
            $table->boolean('is_open')->default(true); // true: open for betting, false: closed
            $table->text('notes')->nullable();
            $table->timestamps();
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('three_d_draw_sessions');
    }
};
