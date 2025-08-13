<!DOCTYPE html>
<html <?php language_attributes(); ?>>
<head>
    <meta charset="<?php bloginfo('charset'); ?>">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title><?php bloginfo('name'); ?></title>
    <?php wp_head(); ?>
</head>
<body <?php body_class(); ?>>
<header>
    <div class="container">
        <div class="site-title">
            <a href="<?php echo esc_url(home_url('/')); ?>" style="color:#fff;text-decoration:none;font-size:2em;">
                <?php bloginfo('name'); ?>
            </a>
        </div>
        <nav>
            <?php
            wp_nav_menu([
                'theme_location' => 'main-menu',
                'container' => false,
                'menu_class' => 'main-menu',
            ]);
            ?>
            <div class="social-icons">
                <a href="#" title="Twitter"><span>🐦</span></a>
                <a href="#" title="Facebook"><span>📘</span></a>
                <a href="#" title="Instagram"><span>📸</span></a>
            </div>
        </nav>
    </div>
</header>
