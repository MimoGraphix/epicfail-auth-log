<?php

use Illuminate\Support\Facades\Schema;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Database\Migrations\Migration;

class CreateAuthenticationLogTable extends Migration
{
    /**
     * Run the migrations.
     *
     * @return void
     */
    public function up()
    {
        Schema::create('authentication_log', function (Blueprint $table) {
            $table->bigIncrements('id');
            $table->morphs('authenticatable');
            $table->string('session_key' )->nullable();
            $table->string('ip_address', 45)->nullable();
            $table->string('location')->nullable();
            $table->text('user_agent')->nullable();
            $table->boolean('flag_remember')->default( 0 );
            $table->string('guard', 25)->nullable( );
            $table->datetime( 'last_active' )->nullable( );
            $table->timestamp('login_at')->nullable();
            $table->timestamp('logout_at')->nullable();
        });
    }

    /**
     * Reverse the migrations.
     *
     * @return void
     */
    public function down()
    {
        Schema::dropIfExists('authentication_log');
    }
}
