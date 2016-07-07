<?php

$finder = Symfony\CS\Finder\DefaultFinder::create()
    ->in(__DIR__ . "/src");

return Symfony\CS\Config\Config::create()
    ->level(\Symfony\CS\FixerInterface::PSR2_LEVEL)
    ->fixers([
        'unused_use',
        'remove_lines_between_uses',
        'remove_leading_slash_use',
        'ordered_use',
        'short_array_syntax',
        'whitespacy_lines',
        'ternary_spaces',
        'standardize_not_equal',
        'spaces_cast',
        'extra_empty_lines',
    ])
    ->finder($finder);
