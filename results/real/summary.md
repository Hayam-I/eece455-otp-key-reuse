# Member D results (real)

Data: real (ciphertexts.json from C)

Trial subsampling stride 3; seed 20261123. Trials vary message pairs and crib positions, not keys.

## E1 - success vs crib length and type (reuse)

| crib_len | crib_type | trials | top1 | top3 | chance_top1 | chance_top3 |
|---|---|---|---|---|---|---|
| 3 | all | 1690 | 0.319 | 0.527 | 0.00592 | 0.0178 |
| 3 | common | 87 | 0.16 | 0.33 | 0.00592 | 0.0178 |
| 3 | rare | 1603 | 0.328 | 0.538 | 0.00592 | 0.0178 |
| 4 | all | 1690 | 0.439 | 0.648 | 0.00596 | 0.0179 |
| 4 | common | 189 | 0.214 | 0.393 | 0.00596 | 0.0179 |
| 4 | rare | 1501 | 0.467 | 0.68 | 0.00596 | 0.0179 |
| 5 | all | 1688 | 0.542 | 0.744 | 0.00601 | 0.018 |
| 5 | common | 300 | 0.333 | 0.553 | 0.00597 | 0.0179 |
| 5 | rare | 1388 | 0.588 | 0.785 | 0.00601 | 0.018 |
| 6 | all | 1660 | 0.654 | 0.827 | 0.00603 | 0.0181 |
| 6 | common | 414 | 0.487 | 0.696 | 0.00602 | 0.0181 |
| 6 | rare | 1246 | 0.709 | 0.871 | 0.00603 | 0.0181 |
| 7 | all | 1660 | 0.727 | 0.863 | 0.00607 | 0.0182 |
| 7 | common | 508 | 0.577 | 0.774 | 0.00607 | 0.0182 |
| 7 | rare | 1152 | 0.793 | 0.903 | 0.00607 | 0.0182 |
| 8 | all | 1658 | 0.78 | 0.906 | 0.00612 | 0.0183 |
| 8 | common | 595 | 0.652 | 0.842 | 0.00606 | 0.0182 |
| 8 | rare | 1063 | 0.852 | 0.942 | 0.00615 | 0.0184 |
| 9 | all | 1630 | 0.833 | 0.93 | 0.00614 | 0.0184 |
| 9 | common | 678 | 0.761 | 0.894 | 0.00612 | 0.0184 |
| 9 | rare | 952 | 0.883 | 0.956 | 0.00615 | 0.0184 |
| 10 | all | 1630 | 0.864 | 0.944 | 0.00618 | 0.0185 |
| 10 | common | 747 | 0.803 | 0.921 | 0.00618 | 0.0185 |
| 10 | rare | 883 | 0.915 | 0.963 | 0.00618 | 0.0186 |
| 11 | all | 1628 | 0.897 | 0.961 | 0.00623 | 0.0187 |
| 11 | common | 812 | 0.852 | 0.946 | 0.00616 | 0.0185 |
| 11 | rare | 816 | 0.941 | 0.975 | 0.0063 | 0.0189 |
| 12 | all | 1600 | 0.924 | 0.976 | 0.00625 | 0.0188 |
| 12 | common | 882 | 0.9 | 0.967 | 0.00621 | 0.0186 |
| 12 | rare | 718 | 0.953 | 0.986 | 0.0063 | 0.0189 |

## E1 - success vs crib length and type (control)

| crib_len | crib_type | trials | top1 | top3 | chance_top1 | chance_top3 |
|---|---|---|---|---|---|---|
| 3 | all | 1690 | 0.00473 | 0.0219 | 0.00592 | 0.0178 |
| 3 | common | 87 | 0 | 0.0115 | 0.00592 | 0.0178 |
| 3 | rare | 1603 | 0.00499 | 0.0225 | 0.00592 | 0.0178 |
| 4 | all | 1690 | 0.00769 | 0.0189 | 0.00596 | 0.0179 |
| 4 | common | 189 | 0.0212 | 0.037 | 0.00596 | 0.0179 |
| 4 | rare | 1501 | 0.006 | 0.0167 | 0.00596 | 0.0179 |
| 5 | all | 1688 | 0.00355 | 0.019 | 0.00601 | 0.018 |
| 5 | common | 300 | 0.00333 | 0.03 | 0.00597 | 0.0179 |
| 5 | rare | 1388 | 0.0036 | 0.0166 | 0.00601 | 0.018 |
| 6 | all | 1660 | 0.00602 | 0.0187 | 0.00603 | 0.0181 |
| 6 | common | 414 | 0.00725 | 0.0266 | 0.00602 | 0.0181 |
| 6 | rare | 1246 | 0.00562 | 0.0161 | 0.00603 | 0.0181 |
| 7 | all | 1660 | 0.00422 | 0.0157 | 0.00607 | 0.0182 |
| 7 | common | 508 | 0.00394 | 0.0276 | 0.00607 | 0.0182 |
| 7 | rare | 1152 | 0.00434 | 0.0104 | 0.00607 | 0.0182 |
| 8 | all | 1658 | 0.00483 | 0.0181 | 0.00612 | 0.0183 |
| 8 | common | 595 | 0.00672 | 0.0235 | 0.00606 | 0.0182 |
| 8 | rare | 1063 | 0.00376 | 0.0151 | 0.00615 | 0.0184 |
| 9 | all | 1630 | 0.00491 | 0.016 | 0.00614 | 0.0184 |
| 9 | common | 678 | 0.00442 | 0.0206 | 0.00612 | 0.0184 |
| 9 | rare | 952 | 0.00525 | 0.0126 | 0.00615 | 0.0184 |
| 10 | all | 1630 | 0.00552 | 0.0209 | 0.00618 | 0.0185 |
| 10 | common | 747 | 0.00669 | 0.0228 | 0.00618 | 0.0185 |
| 10 | rare | 883 | 0.00453 | 0.0193 | 0.00618 | 0.0186 |
| 11 | all | 1628 | 0.00246 | 0.0178 | 0.00623 | 0.0187 |
| 11 | common | 812 | 0.00493 | 0.0222 | 0.00616 | 0.0185 |
| 11 | rare | 816 | 0 | 0.0135 | 0.0063 | 0.0189 |
| 12 | all | 1600 | 0.00562 | 0.0175 | 0.00625 | 0.0188 |
| 12 | common | 882 | 0.00794 | 0.0227 | 0.00621 | 0.0186 |
| 12 | rare | 718 | 0.00279 | 0.0111 | 0.0063 | 0.0189 |

## E2 - success vs number of ciphertexts, 6-char cribs (reuse)

| n_ciphertexts | trials | top1 | top3 | chance_top1 | chance_top3 |
|---|---|---|---|---|---|
| 2 | 308 | 0.531 | 0.656 | 0.00649 | 0.0195 |
| 3 | 425 | 0.774 | 0.92 | 0.00471 | 0.0141 |
| 4 | 402 | 0.838 | 0.963 | 0.00498 | 0.0149 |
| 5 | 443 | 0.901 | 0.973 | 0.00452 | 0.0136 |
| 6 | 443 | 0.912 | 0.977 | 0.00452 | 0.0136 |

## E2 - success vs number of ciphertexts, 6-char cribs (control)

| n_ciphertexts | trials | top1 | top3 | chance_top1 | chance_top3 |
|---|---|---|---|---|---|
| 2 | 266 | 0 | 0.00752 | 0.00752 | 0.0226 |
| 3 | 443 | 0.00677 | 0.00903 | 0.00452 | 0.0136 |
| 4 | 384 | 0.0026 | 0.013 | 0.00521 | 0.0156 |
| 5 | 443 | 0.00451 | 0.00903 | 0.00452 | 0.0136 |
| 6 | 443 | 0.00451 | 0.0135 | 0.00452 | 0.0136 |

## E3 - iterative recovery vs number of ciphertexts (reuse)

| n_ciphertexts | runs | correct | wrong | total | frac_correct | precision | complete_messages | rounds |
|---|---|---|---|---|---|---|---|---|
| 2 | 3 | 20 | 16.7 | 328 | 0.0696 | 0.529 | 0 | 2.67 |
| 3 | 3 | 253 | 24 | 652 | 0.379 | 0.914 | 0 | 5.67 |
| 4 | 3 | 447 | 22.7 | 790 | 0.572 | 0.951 | 0 | 7 |
| 5 | 3 | 736 | 26.7 | 1043 | 0.705 | 0.965 | 0 | 8.67 |
| 6 | 1 | 1061 | 12 | 1357 | 0.782 | 0.989 | 0 | 10 |

## E3 - iterative recovery vs number of ciphertexts (control)

| n_ciphertexts | runs | correct | wrong | total | frac_correct | precision | complete_messages | rounds |
|---|---|---|---|---|---|---|---|---|
| 2 | 1 | 0 | 0 | 532 | 0 | nan | 0 | 0 |
| 3 | 1 | 0 | 0 | 492 | 0 | nan | 0 | 0 |
| 4 | 1 | 0 | 0 | 993 | 0 | nan | 0 | 0 |
| 5 | 1 | 0 | 0 | 1091 | 0 | nan | 0 | 0 |
| 6 | 1 | 0 | 0 | 1357 | 0 | nan | 0 | 0 |

## Ablation (reused key, all ciphertexts)

| variant | correct | wrong | total | frac_correct | precision | complete_messages | rounds |
|---|---|---|---|---|---|---|---|
| full (cribs + commit filter + extension) | 1061 | 12 | 1357 | 0.782 | 0.989 | 0 | 10 |
| no extension | 1037 | 18 | 1357 | 0.764 | 0.983 | 0 | 10 |
| no commit filter | 1105 | 37 | 1357 | 0.814 | 0.968 | 0 | 10 |
| + space heuristic | 1022 | 69 | 1357 | 0.753 | 0.937 | 0 | 6 |
| + joint gap search (tried, off by default) | 1061 | 18 | 1357 | 0.782 | 0.983 | 0 | 10 |

## Definition-of-done check

- Fully automatic: messages recovered completely over the overlap region: 0 of 6 -> DOES NOT meet the 'at least two' target.
- Overlap characters correct (automatic): 1061/1357 (78.2%), wrong: 12.
- With analyst-supplied words after reading the partial text: 6 of 6 complete -> meets the target; 41 analyst guesses in total (27 words, 14 single punctuation/space characters); cumulative guesses, shortest message first: m2: 5, m4: 7, m1: 11, m6: 24, m5: 41, m3: 41. Words supplied: m2@0 'Courier', m2@16 'Thursday', m2@45 'Meet', m2@91 'papers', m2@97 '.', m4@110 'instructions', m4@134 'contact', m1@168 'transmission', m1@182 'Advise', m1@189 'at', m1@191 ' ', m6@202 'meetings', m6@214 'reduced', m6@225 'one', m6@229 'each', m6@234 'month', m6@240 'until', m6@246 'the', m6@250 'matter', m6@256 ' ', m6@257 'is', m6@259 ' ', m6@260 'clear', m6@265 '.', m5@266 ' ', m5@267 'continue', m5@275 ' ', m5@276 'as', m5@278 ' ', m5@279 'before', m5@285 ', ', m5@287 'with', m5@291 ' ', m5@292 'reports', m5@299 ' ', m5@300 'sent', m5@304 ' ', m5@305 'every', m5@310 ' ', m5@311 'evening', m5@318 '.'.
- Control (independent keys, all ciphertexts): 0 correct, 0 wrong of 1357.
