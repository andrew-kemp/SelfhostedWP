<?php
get_header();
?>
<main>
    <section class="blog-list">
        <h1>Blog</h1>
        <?php if (have_posts()) : ?>
            <ul>
                <?php while (have_posts()) : the_post(); ?>
                    <li>
                        <a href="<?php the_permalink(); ?>">
                            <?php the_title(); ?>
                        </a>
                    </li>
                <?php endwhile; ?>
            </ul>
        <?php else : ?>
            <p>No posts found.</p>
        <?php endif; ?>
    </section>
</main>
<?php
get_footer();
