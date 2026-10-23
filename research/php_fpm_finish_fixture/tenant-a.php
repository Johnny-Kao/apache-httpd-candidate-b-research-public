<?php

$marker = preg_replace('/[^A-Za-z0-9_-]/', '', $_GET['marker'] ?? 'POISON');
header('Location: /tenant-b.php', true, 302);

// This is the public php-src #18275 pattern: nested shutdown work calls
// fastcgi_finish_request(), waits, and then emits output after the response
// has been handed back to the FastCGI frontend.
register_shutdown_function(static function () use ($marker): void {
    register_shutdown_function(static function () use ($marker): void {
        fastcgi_finish_request();
        usleep(100000);
        echo "X-Late-From-A: {$marker}\r\n";
    });
});
