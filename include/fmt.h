/*
 * fmt.h - Определение макросов ANSI-escape последовательностей
*/

#define BLUE_TXT "\033[34m" /* Синий цвет текста */
#define GRN_TXT "\033[32m" /* Зеленый увет текста */

#define BOLD_TXT "\033[1m" /* Жирный текст */
#define ITALIC_TXT "\x1b[3m" /* Курсивный текст */

#define GRN_BACKG "\x1b[42m" /* Зеленый фон */
#define YELLOW_BACKG "\x1b[43m" /* Желтый фон */
#define BLUE_BACKG "\x1b[44m" /* Синий фон */
#define LBLUE_BACKG "\x1b[46m" /* Голубой фон */
#define WHITE_BACKG "\x1b[47m" /* Белый фон */

#define RESET "\033[0m" /* Сброс */