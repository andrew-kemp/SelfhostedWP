<?php
// Theme setup
function selfhostedwp_theme_setup() {
    add_theme_support('title-tag');
    register_nav_menus([
        'main-menu' => __('Main Menu', 'selfhostedwp'),
    ]);
}
add_action('after_setup_theme', 'selfhostedwp_theme_setup');

// Enqueue styles
function selfhostedwp_enqueue_styles() {
    wp_enqueue_style('selfhostedwp-style', get_stylesheet_uri());
}
add_action('wp_enqueue_scripts', 'selfhostedwp_enqueue_styles');
