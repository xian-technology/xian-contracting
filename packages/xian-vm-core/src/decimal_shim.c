/* Xian's narrow ownership/context boundary around pinned libmpdec. */
#include "mpdecimal.h"
#include <string.h>

#define XIAN_DECIMAL_MAX_INPUT 131072
#define XIAN_DECIMAL_MAX_WORK 4096
#define XIAN_DECIMAL_MAX_POWER_EXTENT 512
#define XIAN_DECIMAL_MAX_POWER_DIGITS 1024

enum {
    XIAN_DECIMAL_OK,
    XIAN_DECIMAL_INVALID,
    XIAN_DECIMAL_DIVZERO,
    XIAN_DECIMAL_OVERFLOW,
    XIAN_DECIMAL_RESOURCE,
    XIAN_DECIMAL_ARGUMENT,
    XIAN_DECIMAL_UNKNOWN
};

typedef void (*operation_fn)(mpd_t *, const mpd_t *const *,
                             const mpd_context_t *, uint32_t *);
typedef struct {
    const char *name;
    size_t arity;
    int expensive;
    operation_fn run;
} operation;

#define UNARY(name, function) \
static void name(mpd_t *r, const mpd_t *const *a, const mpd_context_t *c, uint32_t *s) \
{ function(r, a[0], c, s); }
#define BINARY(name, function) \
static void name(mpd_t *r, const mpd_t *const *a, const mpd_context_t *c, uint32_t *s) \
{ function(r, a[0], a[1], c, s); }
#define TERNARY(name, function) \
static void name(mpd_t *r, const mpd_t *const *a, const mpd_context_t *c, uint32_t *s) \
{ function(r, a[0], a[1], a[2], c, s); }
#define COPY(name, function) \
static void name(mpd_t *r, const mpd_t *const *a, const mpd_context_t *c, uint32_t *s) \
{ (void)c; function(r, a[0], s); }

COPY(copy, mpd_qcopy)
COPY(copy_abs, mpd_qcopy_abs)
COPY(copy_negate, mpd_qcopy_negate)
UNARY(plus, mpd_qplus)
UNARY(minus, mpd_qminus)
UNARY(absolute, mpd_qabs)
UNARY(normalize, mpd_qreduce)
UNARY(square_root, mpd_qsqrt)
UNARY(exponential, mpd_qexp)
UNARY(logarithm, mpd_qln)
UNARY(logarithm10, mpd_qlog10)
UNARY(decimal_logb, mpd_qlogb)
UNARY(next_minus, mpd_qnext_minus)
UNARY(next_plus, mpd_qnext_plus)
UNARY(integral_value, mpd_qround_to_int)
UNARY(integral_exact, mpd_qround_to_intx)
UNARY(floor_value, mpd_qfloor)
UNARY(ceil_value, mpd_qceil)
UNARY(trunc_value, mpd_qtrunc)
UNARY(invert, mpd_qinvert)
BINARY(add, mpd_qadd)
BINARY(subtract, mpd_qsub)
BINARY(multiply, mpd_qmul)
BINARY(divide, mpd_qdiv)
BINARY(divide_integer, mpd_qdivint)
BINARY(decimal_remainder, mpd_qrem)
BINARY(remainder_near, mpd_qrem_near)
BINARY(power, mpd_qpow)
BINARY(compare, mpd_qcompare)
BINARY(compare_signal, mpd_qcompare_signal)
BINARY(maximum, mpd_qmax)
BINARY(maximum_mag, mpd_qmax_mag)
BINARY(minimum, mpd_qmin)
BINARY(minimum_mag, mpd_qmin_mag)
BINARY(next_toward, mpd_qnext_toward)
BINARY(quantize, mpd_qquantize)
BINARY(scaleb, mpd_qscaleb)
BINARY(shift, mpd_qshift)
BINARY(rotate, mpd_qrotate)
BINARY(logical_and, mpd_qand)
BINARY(logical_or, mpd_qor)
BINARY(logical_xor, mpd_qxor)
TERNARY(decimal_fma, mpd_qfma)
TERNARY(power_mod, mpd_qpowmod)

static void copy_sign(mpd_t *r, const mpd_t *const *a, const mpd_context_t *c, uint32_t *s)
{ (void)c; mpd_qcopy_sign(r, a[0], a[1], s); }
static void compare_total(mpd_t *r, const mpd_t *const *a, const mpd_context_t *c, uint32_t *s)
{ (void)c; (void)s; mpd_compare_total(r, a[0], a[1]); }
static void compare_total_mag(mpd_t *r, const mpd_t *const *a, const mpd_context_t *c, uint32_t *s)
{ (void)c; (void)s; mpd_compare_total_mag(r, a[0], a[1]); }

static const operation operations[] = {
    {"parse", 1, 0, copy}, {"copy_abs", 1, 0, copy_abs},
    {"copy_negate", 1, 0, copy_negate}, {"copy_sign", 2, 0, copy_sign},
    {"plus", 1, 0, plus}, {"minus", 1, 0, minus}, {"abs", 1, 0, absolute},
    {"normalize", 1, 0, normalize}, {"sqrt", 1, 1, square_root},
    {"exp", 1, 1, exponential}, {"ln", 1, 1, logarithm},
    {"log10", 1, 1, logarithm10}, {"logb", 1, 0, decimal_logb},
    {"next_minus", 1, 0, next_minus}, {"next_plus", 1, 0, next_plus},
    {"to_integral", 1, 0, integral_value}, {"to_integral_value", 1, 0, integral_value},
    {"to_integral_exact", 1, 0, integral_exact}, {"floor", 1, 0, floor_value},
    {"ceil", 1, 0, ceil_value}, {"trunc", 1, 0, trunc_value},
    {"logical_invert", 1, 0, invert}, {"add", 2, 0, add}, {"sub", 2, 0, subtract},
    {"mul", 2, 0, multiply}, {"div", 2, 0, divide}, {"divint", 2, 0, divide_integer},
    {"rem", 2, 0, decimal_remainder}, {"remainder_near", 2, 0, remainder_near},
    {"pow", 2, 1, power}, {"compare", 2, 0, compare},
    {"compare_signal", 2, 0, compare_signal}, {"compare_total", 2, 0, compare_total},
    {"compare_total_mag", 2, 0, compare_total_mag},
    {"max", 2, 0, maximum}, {"max_mag", 2, 0, maximum_mag},
    {"min", 2, 0, minimum}, {"min_mag", 2, 0, minimum_mag},
    {"next_toward", 2, 0, next_toward}, {"quantize", 2, 0, quantize},
    {"scaleb", 2, 0, scaleb}, {"shift", 2, 0, shift}, {"rotate", 2, 0, rotate},
    {"logical_and", 2, 0, logical_and}, {"logical_or", 2, 0, logical_or},
    {"logical_xor", 2, 0, logical_xor}, {"fma", 3, 0, decimal_fma},
    {"powmod", 3, 1, power_mod}
};

static const operation *find_operation(const char *name)
{
    size_t i;
    for (i = 0; i < sizeof operations / sizeof operations[0]; ++i) {
        if (strcmp(name, operations[i].name) == 0) return &operations[i];
    }
    return NULL;
}

static int classify_status(uint32_t status)
{
    if (status & MPD_Malloc_error) return XIAN_DECIMAL_RESOURCE;
    if (status & MPD_IEEE_Invalid_operation) return XIAN_DECIMAL_INVALID;
    if (status & MPD_Division_by_zero) return XIAN_DECIMAL_DIVZERO;
    if (status & MPD_Overflow) return XIAN_DECIMAL_OVERFLOW;
    return XIAN_DECIMAL_OK;
}

static int bounded_operand(const mpd_t *a, int expensive)
{
    if (a->digits > XIAN_DECIMAL_MAX_INPUT) return 0;
    if (mpd_isspecial(a)) return 1;
    if (a->exp < -XIAN_DECIMAL_MAX_INPUT || a->exp > XIAN_DECIMAL_MAX_INPUT) return 0;
    if (expensive && (a->digits > XIAN_DECIMAL_MAX_WORK ||
                     a->digits + a->exp > XIAN_DECIMAL_MAX_WORK)) return 0;
    return 1;
}

/* Every allocation stays owned by this function until returned as output. */
int xian_decimal_calculate(const char *name, const char *const *text,
                           size_t count, int rounding, char **output)
{
    const operation *op = find_operation(name);
    mpd_context_t context;
    mpd_t *args[3] = {NULL, NULL, NULL};
    mpd_t *result = NULL;
    uint32_t status = 0;
    int rc = XIAN_DECIMAL_ARGUMENT;
    size_t i;

    *output = NULL;
    if (op == NULL) return XIAN_DECIMAL_UNKNOWN;
    if (count != op->arity || rounding < 0 || rounding >= MPD_ROUND_TRUNC) return rc;
    mpd_defaultcontext(&context);
    context.prec = 91;
    context.emin = -100;
    context.emax = 100;
    context.round = rounding;
    context.clamp = 0;
    context.allcr = 1;
    context.traps = context.status = context.newtrap = 0;

    rc = XIAN_DECIMAL_RESOURCE;
    for (i = 0; i < count; ++i) {
        if (strlen(text[i]) > XIAN_DECIMAL_MAX_INPUT) goto done;
        args[i] = mpd_qnew();
        if (args[i] == NULL) goto done;
        mpd_qset_string_exact(args[i], text[i], &status);
        rc = classify_status(status);
        if (rc != XIAN_DECIMAL_OK) goto done;
        if (!bounded_operand(args[i], op->expensive)) {
            rc = XIAN_DECIMAL_RESOURCE;
            goto done;
        }
        rc = XIAN_DECIMAL_RESOURCE;
    }
    if (op->run == power &&
        (args[0]->digits > XIAN_DECIMAL_MAX_POWER_DIGITS ||
         args[1]->digits > XIAN_DECIMAL_MAX_POWER_DIGITS)) {
        goto done;
    }
    /* Integer powering uses precision proportional to exponent extent and a
     * repeated-squaring loop proportional to its bit length. Raw operand bounds
     * alone allow seconds of unmetered work for long near-one coefficients. */
    if ((op->run == power || op->run == power_mod) &&
        mpd_isfinite(args[1]) && mpd_isinteger(args[1]) &&
        args[1]->digits + args[1]->exp > XIAN_DECIMAL_MAX_POWER_EXTENT) {
        goto done;
    }
    result = mpd_qnew();
    if (result == NULL) goto done;
    op->run(result, (const mpd_t *const *)args, &context, &status);
    rc = classify_status(status);
    if (rc != XIAN_DECIMAL_OK) goto done;
    /* Scientific rendering is bounded by coefficient length plus metadata. */
    if (result->digits > XIAN_DECIMAL_MAX_INPUT) {
        rc = XIAN_DECIMAL_RESOURCE;
        goto done;
    }
    *output = mpd_to_sci(result, 1);
    if (*output == NULL) rc = XIAN_DECIMAL_RESOURCE;

done:
    for (i = 0; i < count; ++i) if (args[i] != NULL) mpd_del(args[i]);
    if (result != NULL) mpd_del(result);
    return rc;
}

void xian_decimal_free(char *text)
{
    if (text != NULL) mpd_free(text);
}
