package com.prgrms.devcourse;

import java.util.concurrent.CompletableFuture;

import static java.util.concurrent.CompletableFuture.runAsync;

public class ThreadLocalApp {

    final static ThreadLocal<Integer> threadLocalValue = new ThreadLocal<>();

    public static void main(String[] args) {
        System.out.println(getCurrentThreadName() + " ### main set value = 1");
        threadLocalValue.set(1);

        a();
        b();

        CompletableFuture<Void> task = runAsync(() -> {

            a();
            b();
        });

        task.join();
    }

    static void a() {
        var value = threadLocalValue.get();
        System.out.println(getCurrentThreadName() + " ### a() : " + value);
    }

    static void b() {
        var value = threadLocalValue.get();
        System.out.println(getCurrentThreadName() + " ### b() : " + value);
    }

    static String getCurrentThreadName() {
        return Thread.currentThread().getName();
    }
}