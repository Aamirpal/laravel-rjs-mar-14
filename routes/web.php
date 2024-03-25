<?php

use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Route;

Route::get('/', function () {
    return view('welcome');
});


Route::get('customers', function () {
    //call mock api to get customers
     $response = Http::get('https://65efc415ead08fa78a50e705.mockapi.io/api/customers');
     return $response->json();
});
