#ifndef lint
static const char yysccsid[] = "@(#)yaccpar	1.9 (Berkeley) 02/21/93";
#endif

#include <stdlib.h>
#include <string.h>

#define YYBYACC 1
#define YYMAJOR 1
#define YYMINOR 9
#define YYPATCH 20070509

#define YYEMPTY (-1)
#define yyclearin    (yychar = YYEMPTY)
#define yyerrok      (yyerrflag = 0)
#define YYRECOVERING (yyerrflag != 0)

extern int yyparse(void);

static int yygrowstack(void);
#define YYPREFIX "yy"
#line 2 "sql.y"
	#include<stdio.h>
	#include"find_str.h"
	extern struct access_ctl_info access_info;
#line 8 "sql.y"

	//#include "y.tab.h"
#line 37 "y.tab.c"
#define NAME 257
#define STRING 258
#define INTNUM 259
#define APPROXNUM 260
#define OR 261
#define AND 262
#define NOT 263
#define COMPARISON 264
#define UPDATE 265
#define SELECT 266
#define INSERT 267
#define DROP 268
#define DELETE 269
#define CREATE 270
#define ALTER 271
#define UMINUS 272
#define ALL 273
#define AMMSC 274
#define ANY 275
#define AS 276
#define ASC 277
#define AUTHORIZATION 278
#define ADD 279
#define BETWEEN 280
#define BY 281
#define CHARACTER 282
#define CHANGE 283
#define CHECK 284
#define CLOSE 285
#define COMMIT 286
#define CONTINUE 287
#define CURRENT 288
#define CURSOR 289
#define COLUMN 290
#define DECIMAL 291
#define DECLARE 292
#define DEFAULT 293
#define DESC 294
#define DISTINCT 295
#define DOUBLE 296
#define DATABASE 297
#define ESCAPE 298
#define EXISTS 299
#define FETCH 300
#define FLOAT 301
#define FOR 302
#define FOREIGN 303
#define FOUND 304
#define FROM 305
#define GOTO 306
#define GRANT 307
#define GROUP 308
#define HAVING 309
#define IN 310
#define INDICATOR 311
#define INTEGER 312
#define INTO 313
#define IS 314
#define KEY 315
#define LANGUAGE 316
#define LIKE 317
#define LIMIT 318
#define MODIFY 319
#define NULLX 320
#define NUMERIC 321
#define OF 322
#define ON 323
#define OPEN 324
#define OPTION 325
#define ORDER 326
#define PARAMETER 327
#define PRECISION 328
#define PRIMARY 329
#define PRIVILEGES 330
#define PROCEDURE 331
#define PUBLIC 332
#define REAL 333
#define REFERENCES 334
#define ROLLBACK 335
#define SCHEMA 336
#define SET 337
#define SMALLINT 338
#define SOME 339
#define SQLCODE 340
#define SQLERROR 341
#define TABLE 342
#define TO 343
#define UNION 344
#define UNIQUE 345
#define USER 346
#define VALUES 347
#define VIEW 348
#define WHENEVER 349
#define WHERE 350
#define WITH 351
#define WORK 352
#define YYERRCODE 256
short yylhs[] = {                                        -1,
    0,    3,    4,    6,    6,    7,    7,    8,    8,    8,
    9,   12,   12,   13,   13,   14,   17,   17,   18,   18,
   18,   18,   18,   18,   18,   18,   18,   15,   15,   15,
   15,   15,   21,   21,   10,   24,   24,   22,   22,   11,
   27,   27,   25,   25,   25,   28,   28,   29,   29,   29,
   29,   29,   26,   26,   30,   30,    3,   32,   35,   35,
   36,   36,   37,   37,   38,   38,   38,    3,   40,   40,
   40,   40,   40,   40,   40,   40,   40,   40,   40,   40,
   41,   42,   43,   44,   45,   46,   55,   55,   56,   56,
   57,   57,   47,   48,   49,   49,   59,   59,   59,   50,
   62,   62,   62,   63,   63,   51,   54,   54,   52,   52,
   52,   52,   67,   67,   67,   67,   67,   67,   67,   67,
   65,   53,   53,   34,   34,   34,   70,   70,   23,   60,
   60,   61,   72,   76,   76,   77,   77,   69,   73,   73,
   79,   79,   74,   74,   75,   75,   80,   80,   20,   20,
   20,   20,   20,   81,   81,   81,   81,   81,   81,   81,
   82,   82,   83,   83,   84,   84,   90,   90,   85,   85,
   86,   86,   86,   86,   91,   91,   87,   92,   92,   92,
   88,   89,   64,   64,   64,   64,   64,   64,   64,   64,
   64,   64,   71,   71,   58,   58,   58,   68,   68,   68,
   93,   93,   93,   93,   19,   19,   19,    1,    1,   66,
   39,   39,   39,   16,   16,   16,   16,   16,   16,   16,
   16,   16,   16,   16,   16,   16,   16,    2,   33,   94,
   78,   31,    3,    3,   95,   95,    5,    5,
};
short yylen[] = {                                         2,
    1,    2,    1,    0,    1,    1,    2,    1,    1,    1,
    6,    1,    3,    1,    1,    3,    0,    2,    2,    3,
    4,    2,    2,    2,    4,    2,    5,    4,    5,    7,
   10,    4,    1,    3,    7,    0,    3,    0,    3,    7,
    0,    3,    2,    1,    1,    1,    3,    1,    1,    1,
    2,    2,    1,    3,    1,    1,    2,    6,    0,    3,
    1,    3,    2,    2,    0,    1,    1,    2,    1,    1,
    1,    1,    1,    1,    1,    1,    1,    1,    1,    1,
    2,    2,    7,    4,    4,    5,    4,    1,    1,    3,
    1,    1,    2,    2,    6,    4,    0,    1,    1,    8,
    0,    1,    3,    3,    3,    5,    1,    3,    3,    3,
    3,    6,    1,    2,    1,    2,    1,    2,    1,    2,
    1,    0,    1,    1,    3,    4,    1,    3,    4,    1,
    1,    5,    2,    1,    3,    1,    2,    2,    0,    3,
    1,    3,    0,    2,    0,    2,    1,    3,    3,    3,
    2,    3,    1,    1,    1,    1,    1,    1,    1,    1,
    3,    3,    6,    5,    5,    4,    0,    2,    4,    3,
    6,    5,    6,    5,    1,    3,    4,    1,    1,    1,
    2,    6,    3,    3,    3,    3,    2,    2,    1,    1,
    1,    3,    1,    3,    1,    1,    1,    1,    2,    3,
    4,    5,    5,    4,    1,    1,    1,    1,    3,    1,
    1,    3,    5,    1,    4,    1,    4,    6,    1,    4,
    6,    1,    1,    1,    4,    1,    2,    1,    1,    1,
    1,    1,    5,    4,    2,    1,    0,    1,
};
short yydefred[] = {                                      0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    1,    0,    3,    0,
    6,    8,    9,   10,    0,    0,   69,   70,   71,   72,
   73,   74,   75,   76,   77,   78,   79,   80,    0,    0,
   98,   99,    0,    0,    0,    0,    0,    0,    0,    0,
    0,  229,   81,   82,    0,    0,    0,   48,   49,   50,
    0,    0,    0,    0,   46,   93,   94,    0,    0,  238,
    2,    0,    7,   57,   68,    0,    0,    0,  205,  206,
  207,    0,    0,  131,    0,  230,  197,    0,  196,  190,
  189,    0,    0,  195,    0,  191,    0,    0,  210,  110,
  111,    0,  109,    0,    0,    0,    0,    0,    0,   51,
   43,   52,    0,    0,    0,  236,    0,    0,  209,  228,
    0,    0,  102,    0,  187,  188,    0,    0,    0,    0,
   96,    0,    0,    0,    0,    0,    0,    0,  199,    0,
    0,   84,  123,    0,    0,    0,    0,    0,    0,    0,
    0,    0,  107,  121,   33,    0,    0,   47,    0,  235,
  234,    0,    0,    0,  106,    0,    0,    0,    0,    0,
  192,    0,    0,  134,    0,    0,    0,    0,    0,  185,
  186,    0,  200,    0,    0,   88,   86,    0,    0,    0,
    0,    0,    0,    0,  153,  154,  155,  156,  157,  158,
  159,  160,    0,    0,    0,    0,    0,    0,   12,   14,
   15,    0,  116,  114,  118,  120,    0,    0,  127,    0,
  124,    0,   39,    0,    0,  233,  105,    0,    0,  103,
    0,  201,    0,    0,  204,  231,  137,    0,   95,    0,
    0,    0,    0,  151,    0,    0,  181,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,  222,    0,  226,  223,   17,
   11,    0,    0,  112,    0,    0,    0,   58,  108,   34,
  232,   55,    0,   53,   56,    0,  213,  203,  202,  135,
    0,    0,    0,    0,   92,    0,   89,   91,   83,    0,
  152,    0,  150,    0,  170,    0,    0,    0,  179,  178,
  180,    0,    0,  162,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,  227,    0,    0,    0,   13,    0,
   35,  128,    0,    0,  125,    0,    0,   40,  100,  141,
    0,    0,    0,  132,  129,   87,    0,    0,  169,    0,
    0,    0,  177,    0,  175,    0,    0,    0,  166,   32,
    0,    0,   28,    0,    0,    0,    0,    0,    0,    0,
    0,   18,    0,    0,    0,   61,    0,  126,    0,   54,
    0,    0,  146,   90,    0,    0,    0,    0,  165,    0,
  172,  174,    0,  168,    0,   29,  215,  220,    0,  225,
  217,    0,    0,    0,   23,   24,   22,    0,   37,   66,
   67,   63,    0,   64,   42,  142,    0,    0,    0,  171,
  173,  176,    0,    0,    0,    0,   20,    0,    0,   62,
  148,  182,    0,  221,  218,   21,   25,    0,    0,   27,
    0,   31,
};
short yydgoto[] = {                                      16,
  172,  155,   17,   18,   71,   19,   20,   21,   22,   23,
   24,  208,  209,  210,  211,  270,  328,  372,   89,  192,
  156,  110,  219,  331,   63,  283,  338,   64,   65,  284,
  285,   25,   53,  220,  278,  375,  376,  412,   90,   26,
   27,   28,   29,   30,   31,   32,   33,   34,   35,   36,
   37,   38,  142,  152,  187,  296,  297,   91,   43,   92,
  131,  122,  123,  194,  153,  100,  150,   94,  143,  221,
   95,  132,  241,  293,  344,  173,  174,  237,  341,  383,
  195,  196,  197,  198,  199,  200,  201,  202,  247,  359,
  357,  315,   96,   97,  118,
};
short yysindex[] = {                                    833,
 -198, -120, -289, -159, -217, -186, -202,  -96, -195,  -96,
  -96,  354,  -96, -180, -247,    0,    0,  119,    0, -119,
    0,    0,    0,    0,  119,  119,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,  139, -145,
    0,    0,  722, -198,  -51, -198, -198, -198, -198, -198,
 -198,    0,    0,    0,  -76,  -84,  229,    0,    0,    0,
  -79,  229,  -34,  257,    0,    0,    0,   18, -105,    0,
    0, -188,    0,    0,    0,   73,   77,  298,    0,    0,
    0,  796,  796,    0,  311,    0,    0,  796,    0,    0,
    0,  -80,  472,    0,  320,    0, -100,  229,    0,    0,
    0,   28,    0,  340,  229,  117,   84,   67,   77,    0,
    0,    0, -198,  604, -105,    0,  130,  119,    0,    0,
  334,  -37,    0,  146,    0,    0,  608,  883, -198,   67,
    0,   55,  796,  796,  796,  796,  796,   67,    0, -254,
  564,    0,    0, -140,  134,  125,  131,  142,  156,   77,
  -29,  376,    0,    0,    0,  198,  102,    0,  119,    0,
    0,  628,  641,   77,    0,  411,  418,  796,  213,  924,
    0,  225,  439,    0,  -41,  686,  182,  165,  165,    0,
    0,  472,    0, -120,  462,    0,    0,  686,  172,  464,
  686,   15,  193,  814,    0,    0,    0,    0,    0,    0,
    0,    0,  476,  197,  205,  482,  640,  211,    0,    0,
    0,  264,    0,    0,    0,    0,  640,  -29,    0, -255,
    0,   67,    0,   77, -196,    0,    0,  472,  209,    0,
  280,    0,  947,  498,    0,    0,    0, -198,    0,  259,
  234,  722, -162,    0,  -96,  282,    0,  -26,  536,  686,
  686, -221, -137,  659,  796,  513,  533,  686,  514,  515,
   77,  517,  521,  235,  525,    0,  529,    0,    0,    0,
    0, -140,  219,    0,  -28,  291,  -32,    0,    0,    0,
    0,    0,  -43,    0,    0,  -96,    0,    0,    0,    0,
  213,  686,  258,  275,    0,  212,    0,    0,    0, -120,
    0,  323,    0,  267,    0,  796,  546,  533,    0,    0,
    0,  763,  472,    0,  464,   -8,  -36,  292,  -18,   77,
   77,  224,  332,  335,    0,  343,  344, -116,    0,  327,
    0,    0,  100,  -29,    0,  309, -196,    0,    0,    0,
  574,   15,  365,    0,    0,    0, -162,  722,    0,   59,
  -36,  292,    0,  796,    0,  584,  226,  533,    0,    0,
  241,  322,    0,  585,  333,  590,  363,  313,  594, -125,
 -198,    0,  310, -108,  592,    0, -108,    0,  315,    0,
  213,  597,    0,    0,  275,  796,  601,  397,    0,  472,
    0,    0,  533,    0,  318,    0,    0,    0,  384,    0,
    0,  385, -114,  686,    0,    0,    0,  609,    0,    0,
    0,    0,  100,    0,    0,    0,  395,  614,  472,    0,
    0,    0, -198,  616,  617,  347,    0,  -15,   77,    0,
    0,    0,  623,    0,    0,    0,    0,  403,   77,    0,
  425,    0,
};
short yyrindex[] = {                                     56,
    0,  788,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,  665,    0,   60,
    0,    0,    0,    0,  665,  665,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,  105,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,  -42,    0,    0,    0,
  356,  -42,    0,  357,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,   19,   10,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,  -27,    0,  -73,    0,  155, -233,    0,    0,
    0,   82,    0,    0,  390,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,  665,    0,    0,
    0,   82,    0,    0,    0,    0,    0,    0,    0,    0,
    0,  399,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,  410,  420,  426,   73,    0,
    0,  107,    0,    0,    0,    0,    0,    0,  665,    0,
    0,    0,    0,    0,    0,   32,    0,    0,    0,    0,
    0,   83,  238,    0,    0,    0,  450,  216,  288,    0,
    0,  -13,    0,  788,    0,    0,    0,    0,    0,    0,
    0,  430,  770,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,  122,
    0,    0,    0,    0,    0,    0,    0,   22,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
  454,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,   21,   72,    0,  204,    0,  571,    0,    0,    0,
    0,    0,   36,    0,    0,    0,    0,    0,    0,    0,
    0,    0,   41,    0,    0,    0,    0,    0,    0,    0,
    0,    0,  402,    0,    0,    0,    0,    0,    0,  788,
    0,  352,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,  167,    0,    0,    0,    0,  266,    0,    0,
    0,    0,    0,    0,    0,    0,    0,  443,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
  451,  500,    0,    0,    0,    0,    0,    0,    0,    0,
    0,  266,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,   64,  128,    0,   64,    0,    0,    0,
    0,  503,    0,    0,    0,    0,    0,    0,    0,  338,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,  -35,    0,    0,    0,    0,  491,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,  367,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,  457,    0,    0,    0,    0,    0,    0,    0,
    0,    0,
};
short yygindex[] = {                                      0,
   -1,   26,    0,    0,   61,    0,    0,  667,    0,    0,
    0,    0,  419,    0,    0,  473,    0,    0,  324, -121,
 -236,  112, -102,    0,    0,    0,    0,    0,  578,  360,
    0,    0,   17,  480,    0,    0,  297,  328,  751,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,   87,  582,    0,    0,  366, -199, -179, -228,
 -155,    0,  537,  652,  492,    0,    0,  -90,    0, -209,
    0,    0,    0,    0,    0,    0,  477,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0, -225,  364,
  368,    0,    0,   53,  607,
};
#define YYTABLESIZE 1182
short yytable[] = {                                      40,
  337,   38,  222,  246,  242,   19,  164,  218,   19,  211,
  218,  184,  332,  294,  301,   68,  193,  154,  101,  239,
  214,  104,  360,   44,  322,  437,   55,   56,  314,   66,
  194,  212,   38,  135,  133,   36,  134,  186,  136,  154,
   41,  304,   98,  298,  101,  102,  103,  104,  105,  106,
  211,  211,  211,  211,  211,    4,  211,  318,   39,    5,
  281,  214,  101,   65,  214,  104,  244,  335,  211,  248,
  276,  219,  212,  212,  212,  212,  212,  101,  212,  214,
  104,  122,  136,  361,  362,   74,   75,   47,  277,  353,
  212,  356,  185,   69,   36,   79,   80,   81,  305,   41,
  135,  133,  121,  134,  208,  136,   85,   65,  352,  273,
   48,  157,  219,   38,    4,  219,  120,  355,    5,  385,
  348,   59,   65,  136,  378,  387,  136,   60,  302,  303,
  219,  154,   79,   80,   81,  282,  319,   45,  345,   51,
  122,  136,  306,  203,  208,  208,  368,  298,  208,  139,
   72,  355,   41,   49,  198,   49,   54,  295,  394,   50,
   52,   50,  204,  208,   86,   85,  161,  369,  410,  207,
  342,   67,  307,  112,   42,  217,  370,   70,  161,  308,
   59,  116,   46,   87,   76,  411,   60,   12,  205,  121,
  183,   77,  438,  422,  405,  198,  198,  198,  198,  198,
  117,  198,  441,  224,  206,   99,  135,  161,  165,  140,
  138,  136,  107,  198,  426,  183,  145,  371,  177,  226,
  406,   79,   80,   81,  129,  161,   86,   19,  108,  418,
  427,  130,  130,  184,  250,  251,  184,  133,  223,  130,
  334,  224,  250,  251,  224,  250,  251,  224,   19,  280,
  111,  271,  346,  354,  272,  347,  183,   19,  183,  183,
  183,  299,  224,  129,  363,  167,  392,  224,  109,  393,
  211,  211,  211,  211,  183,  250,  251,  193,  133,  211,
   38,  395,  428,  214,  224,  193,  211,  184,  113,  211,
   86,  194,  212,  212,  212,  212,  133,  207,   19,  194,
  114,  212,  339,  211,  214,   36,  167,  336,  212,   87,
   41,  212,  163,  214,  211,  277,  211,  211,  211,  211,
  386,  115,  211,  211,  167,  212,  211,  211,  184,  119,
  184,  184,  184,  120,  219,  211,  212,  164,  212,  212,
  212,  212,   36,  124,  212,  212,  184,   41,  212,  212,
  127,  149,  136,  211,  214,  219,   78,  212,  374,  211,
  211,  208,  396,  137,  219,  224,  163,  208,  101,  408,
  208,  104,  208,  398,  208,  212,  399,  141,  164,  144,
  208,  212,  212,  208,  146,  151,  160,  208,  208,  136,
  136,  136,  149,   86,  162,  147,  164,  208,  122,  148,
  136,  145,  166,  401,  176,  219,  402,  163,  136,  212,
  149,  208,  208,  208,  213,  198,  198,  198,  198,  222,
  214,  433,  208,  208,  198,  163,  136,  161,  161,  138,
  208,  215,  136,  136,  198,  149,  161,  421,  208,  122,
  393,  208,  145,  440,  225,  216,  224,  208,  208,  139,
  140,  208,  198,  143,  208,  208,  231,  122,  232,  198,
  145,  198,  198,  198,  198,  442,  224,  198,  224,   78,
  138,  198,  198,  161,  161,  161,  183,  183,  183,  183,
  198,  236,  238,   16,  161,  183,   16,  224,  138,  240,
  139,  140,  161,  245,  143,  183,  224,   30,  198,  144,
   30,  243,  147,  246,  198,  198,  252,  133,  139,  140,
  161,  259,  143,  135,  133,  258,  134,  161,  136,  260,
  183,  261,  183,  183,  183,  183,  167,  167,  183,  184,
  286,   26,  183,  183,   26,  167,  287,  224,  289,  291,
  144,  183,  292,  147,  133,  133,  133,  300,  184,  184,
  184,  184,  317,  320,  321,  133,  323,  184,  144,  183,
  324,  147,  325,  133,  326,  183,  183,  184,  327,  330,
  216,  333,  167,  167,  167,  343,  171,  135,  133,  129,
  134,  133,  136,  167,  251,  351,  349,  133,  133,  358,
  364,  167,  184,  365,  184,  184,  184,  184,  164,  164,
  184,  366,  367,  191,  184,  184,   82,  164,   83,  167,
  373,  216,  149,  184,  216,  379,  167,  381,   57,   58,
   59,  149,   60,  382,  391,  397,   61,  163,  163,  216,
  400,  184,  403,  404,  409,  413,  163,  184,  184,  415,
  417,  420,  424,  425,  164,  164,  164,   88,  429,  167,
   82,  423,   83,  431,  432,  164,  434,  435,  149,  149,
  149,  436,  439,  164,  237,   38,  115,   88,  122,  149,
   82,  145,   83,  163,  163,  163,  113,  149,   44,   45,
  191,  164,  117,   82,  163,   83,   73,   62,  164,  274,
  329,  158,  163,  407,   93,  149,  380,  275,  312,  138,
  230,   82,  149,   83,  414,  122,  122,  122,  145,  430,
  163,  175,  384,  279,  290,  389,  122,  163,  388,  139,
  140,  159,    0,  143,  122,  191,    0,  145,   82,    0,
   83,    0,    0,  125,  126,    0,  138,  138,  138,  128,
    0,    0,  122,    0,    0,  145,    0,  138,    0,  122,
    0,    0,  145,   26,    0,  138,  139,  140,  139,  140,
  143,   88,    0,   84,   82,    0,   83,  139,  140,  144,
    0,  143,  147,  138,   26,  139,  140,    0,  170,  143,
  138,    0,    0,   26,  178,  179,  180,  181,  182,    0,
   79,   80,   81,  139,  140,    0,    0,  143,  253,  254,
  139,  140,   88,    0,  143,   82,  144,   83,    0,  147,
  190,  190,  190,  228,  190,  255,  190,  144,    0,  233,
   78,   79,   80,   81,   26,  144,  188,   97,  147,   97,
   97,    0,   97,  216,    0,   88,    0,   85,   82,    0,
   83,    0,  249,  144,    0,  256,  147,    0,    0,    0,
  144,  189,  257,  147,  216,  135,  133,    0,  134,   86,
  136,    0,  190,  216,   78,   79,   80,   81,   57,   58,
   59,    0,   60,    0,    0,    0,    0,    0,   87,    0,
  168,   85,    0,    0,   78,   79,   80,   81,    0,    0,
   86,  193,    0,   93,    0,    0,    0,   78,   79,   80,
   81,   85,  169,  188,  216,  313,  316,    0,    0,   87,
    0,    0,    0,  193,   85,   78,   79,   80,   81,  234,
    0,  262,    0,  171,  135,  133,  193,  134,  229,  136,
  263,  309,   85,  310,   86,  264,    0,   62,  193,  190,
  265,  193,   78,   79,   80,   81,    0,  227,  188,    0,
    0,  266,    0,   87,   86,    0,    0,  350,    0,   85,
  267,    0,    0,  128,  235,  135,  133,   86,  134,    0,
  136,    0,  268,   87,    0,    0,    0,  269,   78,   79,
   80,   81,    0,    0,  190,   86,   87,  288,  135,  133,
    0,  134,    0,  136,    0,   85,    0,  311,    0,   93,
  193,  193,    0,    0,   87,  390,    0,    0,  193,    0,
    0,    0,   86,    0,    0,    0,    0,    0,    0,   78,
   79,   80,   81,    0,    0,    0,    0,    0,  300,    0,
    0,   87,  190,  190,    0,    0,   85,  419,    0,    0,
    0,  340,  193,    0,   97,   97,   97,   97,   86,  190,
    0,    0,   78,   79,   80,   81,    0,    0,    0,    0,
    0,   97,    0,    0,    0,    0,    0,   87,    0,   85,
    0,    0,    0,    0,    0,    0,  253,  254,    0,  190,
    0,    0,    0,  377,    0,    0,  190,    0,    0,   86,
    0,    0,    0,  255,    0,    0,    0,    1,    2,    3,
    4,    5,    6,    7,    0,    0,    0,    0,   87,    0,
    0,    0,    0,    0,   97,    0,    0,    8,    9,    0,
    0,    0,   86,  256,   10,    0,    0,    0,    0,    0,
  257,  416,   11,   97,    0,    0,    0,    0,    0,   12,
    0,   87,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,  193,    0,   13,    0,    0,    0,
    0,    0,    0,  377,    0,    0,    0,   14,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,   15,
};
short yycheck[] = {                                       1,
   44,   44,   44,   40,  184,   41,   44,   40,   44,    0,
   40,  266,   41,  242,   41,  263,   44,  108,    0,  175,
    0,    0,   41,  313,  261,   41,   10,   11,  254,   13,
   44,    0,  266,   42,   43,    0,   45,  140,   47,  130,
    0,  263,   44,  243,   46,   47,   48,   49,   50,   51,
   41,   42,   43,   44,   45,    0,   47,  257,  257,    0,
  257,   41,   44,    0,   44,   44,  188,  277,   59,  191,
  326,    0,   41,   42,   43,   44,   45,   59,   47,   59,
   59,    0,    0,  320,  321,   25,   26,  305,  344,  315,
   59,  317,  347,  341,   59,  258,  259,  260,  320,   59,
   42,   43,   77,   45,    0,   47,    0,   44,  308,  212,
  297,  113,   41,  347,   59,   44,  257,  317,   59,  348,
  300,    0,   59,   41,  334,  351,   44,    0,  250,  251,
   59,  222,  258,  259,  260,  332,  258,  297,  294,  342,
   59,   59,  280,  284,   40,   41,  263,  347,   44,   97,
  270,  351,  273,  342,    0,  342,  352,  320,  358,  348,
  257,  348,  303,   59,  327,   59,    0,  284,  277,  144,
  292,  352,  310,   62,  295,  150,  293,   59,  118,  317,
   59,  287,  342,  346,   46,  294,   59,  307,  329,  164,
  138,  337,  429,  393,  320,   41,   42,   43,   44,   45,
  306,   47,  439,    0,  345,  257,   42,   41,  122,   98,
  311,   47,  289,   59,  329,    0,  105,  334,  132,  159,
  346,  258,  259,  260,  305,   59,  327,  263,  313,  385,
  345,  305,  313,  266,  261,  262,  266,    0,   41,  313,
  273,   44,  261,  262,   41,  261,  262,   44,  284,  224,
  330,   41,   41,  262,   44,   44,   41,  293,   43,   44,
   45,  245,   59,  305,   41,    0,   41,   44,   40,   44,
  261,  262,  263,  264,   59,  261,  262,  305,   41,  270,
  323,   41,  404,  263,   44,  313,  277,    0,  323,  280,
  327,  305,  261,  262,  263,  264,   59,  272,  334,  313,
   44,  270,  286,  294,  284,  270,   41,  351,  277,  346,
  270,  280,  350,  293,  305,  344,  307,  308,  309,  310,
  262,  304,  313,  314,   59,  294,  317,  318,   41,  257,
   43,   44,   45,  257,  263,  326,  305,    0,  307,  308,
  309,  310,  307,   46,  313,  314,   59,  307,  317,  318,
   40,    0,  270,  344,  334,  284,  257,  326,  259,  350,
  351,  257,   41,   44,  293,   44,    0,  263,  350,  371,
  266,  350,  268,   41,  270,  344,   44,  350,   41,   40,
  276,  350,  351,  279,  268,  302,  257,  283,  284,  307,
  308,  309,   41,  327,   61,  279,   59,  293,    0,  283,
  318,    0,  257,   41,  350,  334,   44,   41,  326,  276,
   59,  307,  308,  309,  290,  261,  262,  263,  264,   44,
  290,  423,  318,  319,  270,   59,  344,  261,  262,    0,
  326,  290,  350,  351,  280,  319,  270,   41,  334,   41,
   44,  337,   41,   41,  343,  290,   44,  343,  344,    0,
    0,  347,  298,    0,  350,  351,   46,   59,   41,  305,
   59,  307,  308,  309,  310,   41,  263,  313,   44,  257,
   41,  317,  318,  307,  308,  309,  261,  262,  263,  264,
  326,  257,   44,   41,  318,  270,   44,  284,   59,  308,
   41,   41,  326,  322,   41,  280,  293,   41,  344,    0,
   44,   40,    0,   40,  350,  351,  314,  270,   59,   59,
  344,  315,   59,   42,   43,   40,   45,  351,   47,  315,
  305,   40,  307,  308,  309,  310,  261,  262,  313,  266,
  322,   41,  317,  318,   44,  270,  257,  334,   41,  281,
   41,  326,  309,   41,  307,  308,  309,  266,  261,  262,
  263,  264,   40,   40,   40,  318,   40,  270,   59,  344,
   40,   59,  328,  326,   40,  350,  351,  280,   40,  351,
    0,  281,  307,  308,  309,  318,   41,   42,   43,  305,
   45,  344,   47,  318,  262,   40,  320,  350,  351,  298,
  259,  326,  305,  259,  307,  308,  309,  310,  261,  262,
  313,  259,  259,   40,  317,  318,   43,  270,   45,  344,
  284,   41,  261,  326,   44,  307,  351,   44,  265,  266,
  267,  270,  269,  259,   41,   41,  273,  261,  262,   59,
   41,  344,  320,   40,  325,   44,  270,  350,  351,  325,
   44,   41,  259,  259,  307,  308,  309,   40,   40,   42,
   43,  334,   45,  259,   41,  318,   41,   41,  307,  308,
  309,  315,   40,  326,    0,  276,  257,   40,  270,  318,
   43,  270,   45,  307,  308,  309,  257,  326,  323,  323,
   40,  344,  257,   43,  318,   45,   20,  334,  351,  217,
  272,  114,  326,  370,   43,  344,  337,  218,   40,  270,
  164,   43,  351,   45,  377,  307,  308,  309,  307,  413,
  344,  130,  347,  222,  238,  352,  318,  351,  351,  270,
  270,  115,   -1,  270,  326,   40,   -1,  326,   43,   -1,
   45,   -1,   -1,   82,   83,   -1,  307,  308,  309,   88,
   -1,   -1,  344,   -1,   -1,  344,   -1,  318,   -1,  351,
   -1,   -1,  351,  263,   -1,  326,  307,  307,  309,  309,
  307,   40,   -1,   42,   43,   -1,   45,  318,  318,  270,
   -1,  318,  270,  344,  284,  326,  326,   -1,  127,  326,
  351,   -1,   -1,  293,  133,  134,  135,  136,  137,   -1,
  258,  259,  260,  344,  344,   -1,   -1,  344,  263,  264,
  351,  351,   40,   -1,  351,   43,  307,   45,   -1,  307,
   41,   42,   43,  162,   45,  280,   47,  318,   -1,  168,
  257,  258,  259,  260,  334,  326,  263,   40,  326,   42,
   43,   -1,   45,  263,   -1,   40,   -1,  274,   43,   -1,
   45,   -1,  191,  344,   -1,  310,  344,   -1,   -1,   -1,
  351,  288,  317,  351,  284,   42,   43,   -1,   45,  327,
   47,   -1,  299,  293,  257,  258,  259,  260,  265,  266,
  267,   -1,  269,   -1,   -1,   -1,   -1,   -1,  346,   -1,
  273,  274,   -1,   -1,  257,  258,  259,  260,   -1,   -1,
  327,  141,   -1,  242,   -1,   -1,   -1,  257,  258,  259,
  260,  274,  295,  263,  334,  254,  255,   -1,   -1,  346,
   -1,   -1,   -1,  163,  274,  257,  258,  259,  260,  169,
   -1,  282,   -1,   41,   42,   43,  176,   45,  288,   47,
  291,  273,  274,  275,  327,  296,   -1,  334,  188,  299,
  301,  191,  257,  258,  259,  260,   -1,  320,  263,   -1,
   -1,  312,   -1,  346,  327,   -1,   -1,  306,   -1,  274,
  321,   -1,   -1,  312,   41,   42,   43,  327,   45,   -1,
   47,   -1,  333,  346,   -1,   -1,   -1,  338,  257,  258,
  259,  260,   -1,   -1,  299,  327,  346,   41,   42,   43,
   -1,   45,   -1,   47,   -1,  274,   -1,  339,   -1,  348,
  250,  251,   -1,   -1,  346,  354,   -1,   -1,  258,   -1,
   -1,   -1,  327,   -1,   -1,   -1,   -1,   -1,   -1,  257,
  258,  259,  260,   -1,   -1,   -1,   -1,   -1,  266,   -1,
   -1,  346,  263,  264,   -1,   -1,  274,  386,   -1,   -1,
   -1,  291,  292,   -1,  257,  258,  259,  260,  327,  280,
   -1,   -1,  257,  258,  259,  260,   -1,   -1,   -1,   -1,
   -1,  274,   -1,   -1,   -1,   -1,   -1,  346,   -1,  274,
   -1,   -1,   -1,   -1,   -1,   -1,  263,  264,   -1,  310,
   -1,   -1,   -1,  333,   -1,   -1,  317,   -1,   -1,  327,
   -1,   -1,   -1,  280,   -1,   -1,   -1,  265,  266,  267,
  268,  269,  270,  271,   -1,   -1,   -1,   -1,  346,   -1,
   -1,   -1,   -1,   -1,  327,   -1,   -1,  285,  286,   -1,
   -1,   -1,  327,  310,  292,   -1,   -1,   -1,   -1,   -1,
  317,  381,  300,  346,   -1,   -1,   -1,   -1,   -1,  307,
   -1,  346,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,  404,   -1,  324,   -1,   -1,   -1,
   -1,   -1,   -1,  413,   -1,   -1,   -1,  335,   -1,   -1,
   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,   -1,
   -1,  349,
};
#define YYFINAL 16
#ifndef YYDEBUG
#define YYDEBUG 0
#endif
#define YYMAXTOKEN 352
#if YYDEBUG
char *yyname[] = {
"end-of-file",0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,"'('","')'","'*'","'+'","','","'-'","'.'","'/'",0,0,0,0,0,0,0,0,0,0,
0,"';'",0,"'='",0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,"NAME","STRING","INTNUM","APPROXNUM","OR","AND","NOT","COMPARISON",
"UPDATE","SELECT","INSERT","DROP","DELETE","CREATE","ALTER","UMINUS","ALL",
"AMMSC","ANY","AS","ASC","AUTHORIZATION","ADD","BETWEEN","BY","CHARACTER",
"CHANGE","CHECK","CLOSE","COMMIT","CONTINUE","CURRENT","CURSOR","COLUMN",
"DECIMAL","DECLARE","DEFAULT","DESC","DISTINCT","DOUBLE","DATABASE","ESCAPE",
"EXISTS","FETCH","FLOAT","FOR","FOREIGN","FOUND","FROM","GOTO","GRANT","GROUP",
"HAVING","IN","INDICATOR","INTEGER","INTO","IS","KEY","LANGUAGE","LIKE","LIMIT",
"MODIFY","NULLX","NUMERIC","OF","ON","OPEN","OPTION","ORDER","PARAMETER",
"PRECISION","PRIMARY","PRIVILEGES","PROCEDURE","PUBLIC","REAL","REFERENCES",
"ROLLBACK","SCHEMA","SET","SMALLINT","SOME","SQLCODE","SQLERROR","TABLE","TO",
"UNION","UNIQUE","USER","VALUES","VIEW","WHENEVER","WHERE","WITH","WORK",
};
char *yyrule[] = {
"$accept : start_sql",
"start_sql : sql",
"sql : schema opt_semicolon",
"schema : opt_schema_element_list",
"opt_schema_element_list :",
"opt_schema_element_list : schema_element_list",
"schema_element_list : schema_element",
"schema_element_list : schema_element_list schema_element",
"schema_element : base_table_def",
"schema_element : view_def",
"schema_element : privilege_def",
"base_table_def : CREATE TABLE tbname '(' base_table_element_commalist ')'",
"base_table_element_commalist : base_table_element",
"base_table_element_commalist : base_table_element_commalist ',' base_table_element",
"base_table_element : column_def",
"base_table_element : table_constraint_def",
"column_def : column data_type column_def_opt_list",
"column_def_opt_list :",
"column_def_opt_list : column_def_opt_list column_def_opt",
"column_def_opt : NOT NULLX",
"column_def_opt : NOT NULLX UNIQUE",
"column_def_opt : NOT NULLX PRIMARY KEY",
"column_def_opt : DEFAULT literal",
"column_def_opt : DEFAULT NULLX",
"column_def_opt : DEFAULT USER",
"column_def_opt : CHECK '(' search_condition ')'",
"column_def_opt : REFERENCES tbname",
"column_def_opt : REFERENCES tbname '(' column_commalist ')'",
"table_constraint_def : UNIQUE '(' column_commalist ')'",
"table_constraint_def : PRIMARY KEY '(' column_commalist ')'",
"table_constraint_def : FOREIGN KEY '(' column_commalist ')' REFERENCES tbname",
"table_constraint_def : FOREIGN KEY '(' column_commalist ')' REFERENCES tbname '(' column_commalist ')'",
"table_constraint_def : CHECK '(' search_condition ')'",
"column_commalist : column",
"column_commalist : column_commalist ',' column",
"view_def : CREATE VIEW tbname opt_column_commalist AS query_spec opt_with_check_option",
"opt_with_check_option :",
"opt_with_check_option : WITH CHECK OPTION",
"opt_column_commalist :",
"opt_column_commalist : '(' column_commalist ')'",
"privilege_def : GRANT privileges ON tbname TO grantee_commalist opt_with_grant_option",
"opt_with_grant_option :",
"opt_with_grant_option : WITH GRANT OPTION",
"privileges : ALL PRIVILEGES",
"privileges : ALL",
"privileges : operation_commalist",
"operation_commalist : operation",
"operation_commalist : operation_commalist ',' operation",
"operation : SELECT",
"operation : INSERT",
"operation : DELETE",
"operation : UPDATE opt_column_commalist",
"operation : REFERENCES opt_column_commalist",
"grantee_commalist : grantee",
"grantee_commalist : grantee_commalist ',' grantee",
"grantee : PUBLIC",
"grantee : user",
"sql : cursor_def opt_semicolon",
"cursor_def : DECLARE cursor CURSOR FOR query_exp opt_order_by_clause",
"opt_order_by_clause :",
"opt_order_by_clause : ORDER BY ordering_spec_commalist",
"ordering_spec_commalist : ordering_spec",
"ordering_spec_commalist : ordering_spec_commalist ',' ordering_spec",
"ordering_spec : INTNUM opt_asc_desc",
"ordering_spec : column_ref opt_asc_desc",
"opt_asc_desc :",
"opt_asc_desc : ASC",
"opt_asc_desc : DESC",
"sql : manipulative_statement opt_semicolon",
"manipulative_statement : close_statement",
"manipulative_statement : commit_statement",
"manipulative_statement : delete_statement_positioned",
"manipulative_statement : delete_statement_searched",
"manipulative_statement : fetch_statement",
"manipulative_statement : insert_statement",
"manipulative_statement : open_statement",
"manipulative_statement : rollback_statement",
"manipulative_statement : select_statement",
"manipulative_statement : update_statement_positioned",
"manipulative_statement : update_statement_searched",
"manipulative_statement : database_statement",
"close_statement : CLOSE cursor",
"commit_statement : COMMIT WORK",
"delete_statement_positioned : DELETE FROM tbname WHERE CURRENT OF cursor",
"delete_statement_searched : DELETE FROM tbname opt_where_clause",
"fetch_statement : FETCH cursor INTO target_commalist",
"insert_statement : INSERT INTO tbname opt_column_commalist values_or_query_spec",
"values_or_query_spec : VALUES '(' insert_atom_commalist ')'",
"values_or_query_spec : query_spec",
"insert_atom_commalist : insert_atom",
"insert_atom_commalist : insert_atom_commalist ',' insert_atom",
"insert_atom : atom",
"insert_atom : NULLX",
"open_statement : OPEN cursor",
"rollback_statement : ROLLBACK WORK",
"select_statement : SELECT opt_all_distinct selection INTO target_commalist table_exp",
"select_statement : SELECT opt_all_distinct selection table_exp",
"opt_all_distinct :",
"opt_all_distinct : ALL",
"opt_all_distinct : DISTINCT",
"update_statement_positioned : UPDATE tbname SET assignment_commalist WHERE CURRENT OF cursor",
"assignment_commalist :",
"assignment_commalist : assignment",
"assignment_commalist : assignment_commalist ',' assignment",
"assignment : column '=' scalar_exp",
"assignment : column '=' NULLX",
"update_statement_searched : UPDATE tbname SET assignment_commalist opt_where_clause",
"target_commalist : target",
"target_commalist : target_commalist ',' target",
"database_statement : CREATE DATABASE tbname",
"database_statement : DROP DATABASE dbname",
"database_statement : DROP TABLE tbname",
"database_statement : ALTER TABLE tbname act_option column data_type",
"act_option : ADD",
"act_option : ADD COLUMN",
"act_option : DROP",
"act_option : DROP COLUMN",
"act_option : CHANGE",
"act_option : CHANGE COLUMN",
"act_option : MODIFY",
"act_option : MODIFY COLUMN",
"target : parameter_ref",
"opt_where_clause :",
"opt_where_clause : where_clause",
"query_exp : query_term",
"query_exp : query_exp UNION query_term",
"query_exp : query_exp UNION ALL query_term",
"query_term : query_spec",
"query_term : '(' query_exp ')'",
"query_spec : SELECT opt_all_distinct selection table_exp",
"selection : scalar_exp_commalist",
"selection : '*'",
"table_exp : from_clause opt_where_clause opt_group_by_clause opt_having_clause opt_limit_clause",
"from_clause : FROM table_ref_commalist",
"table_ref_commalist : table_ref",
"table_ref_commalist : table_ref_commalist ',' table_ref",
"table_ref : tbname",
"table_ref : tbname range_variable",
"where_clause : WHERE search_condition",
"opt_group_by_clause :",
"opt_group_by_clause : GROUP BY column_ref_commalist",
"column_ref_commalist : column_ref",
"column_ref_commalist : column_ref_commalist ',' column_ref",
"opt_having_clause :",
"opt_having_clause : HAVING search_condition",
"opt_limit_clause :",
"opt_limit_clause : LIMIT range",
"range : INTNUM",
"range : INTNUM ',' INTNUM",
"search_condition : search_condition OR search_condition",
"search_condition : search_condition AND search_condition",
"search_condition : NOT search_condition",
"search_condition : '(' search_condition ')'",
"search_condition : predicate",
"predicate : comparison_predicate",
"predicate : between_predicate",
"predicate : like_predicate",
"predicate : test_for_null",
"predicate : in_predicate",
"predicate : all_or_any_predicate",
"predicate : existence_test",
"comparison_predicate : scalar_exp COMPARISON scalar_exp",
"comparison_predicate : scalar_exp COMPARISON subquery",
"between_predicate : scalar_exp NOT BETWEEN scalar_exp AND scalar_exp",
"between_predicate : scalar_exp BETWEEN scalar_exp AND scalar_exp",
"like_predicate : scalar_exp NOT LIKE atom opt_escape",
"like_predicate : scalar_exp LIKE atom opt_escape",
"opt_escape :",
"opt_escape : ESCAPE atom",
"test_for_null : column_ref IS NOT NULLX",
"test_for_null : column_ref IS NULLX",
"in_predicate : scalar_exp NOT IN '(' subquery ')'",
"in_predicate : scalar_exp IN '(' subquery ')'",
"in_predicate : scalar_exp NOT IN '(' atom_commalist ')'",
"in_predicate : scalar_exp IN '(' atom_commalist ')'",
"atom_commalist : atom",
"atom_commalist : atom_commalist ',' atom",
"all_or_any_predicate : scalar_exp COMPARISON any_all_some subquery",
"any_all_some : ANY",
"any_all_some : ALL",
"any_all_some : SOME",
"existence_test : EXISTS subquery",
"subquery : '(' SELECT opt_all_distinct selection table_exp ')'",
"scalar_exp : scalar_exp '+' scalar_exp",
"scalar_exp : scalar_exp '-' scalar_exp",
"scalar_exp : scalar_exp '*' scalar_exp",
"scalar_exp : scalar_exp '/' scalar_exp",
"scalar_exp : '+' scalar_exp",
"scalar_exp : '-' scalar_exp",
"scalar_exp : atom",
"scalar_exp : column_ref",
"scalar_exp : function_ref",
"scalar_exp : '(' scalar_exp ')'",
"scalar_exp_commalist : scalar_exp",
"scalar_exp_commalist : scalar_exp_commalist ',' scalar_exp",
"atom : parameter_ref",
"atom : literal",
"atom : USER",
"parameter_ref : parameter",
"parameter_ref : parameter parameter",
"parameter_ref : parameter INDICATOR parameter",
"function_ref : AMMSC '(' '*' ')'",
"function_ref : AMMSC '(' DISTINCT column_ref ')'",
"function_ref : AMMSC '(' ALL scalar_exp ')'",
"function_ref : AMMSC '(' scalar_exp ')'",
"literal : STRING",
"literal : INTNUM",
"literal : APPROXNUM",
"tbname : NAME",
"tbname : NAME '.' NAME",
"dbname : NAME",
"column_ref : NAME",
"column_ref : NAME '.' NAME",
"column_ref : NAME '.' NAME '.' NAME",
"data_type : CHARACTER",
"data_type : CHARACTER '(' INTNUM ')'",
"data_type : NUMERIC",
"data_type : NUMERIC '(' INTNUM ')'",
"data_type : NUMERIC '(' INTNUM ',' INTNUM ')'",
"data_type : DECIMAL",
"data_type : DECIMAL '(' INTNUM ')'",
"data_type : DECIMAL '(' INTNUM ',' INTNUM ')'",
"data_type : INTEGER",
"data_type : SMALLINT",
"data_type : FLOAT",
"data_type : FLOAT '(' INTNUM ')'",
"data_type : REAL",
"data_type : DOUBLE PRECISION",
"column : NAME",
"cursor : NAME",
"parameter : PARAMETER",
"range_variable : NAME",
"user : NAME",
"sql : WHENEVER NOT FOUND when_action opt_semicolon",
"sql : WHENEVER SQLERROR when_action opt_semicolon",
"when_action : GOTO NAME",
"when_action : CONTINUE",
"opt_semicolon :",
"opt_semicolon : ';'",
};
#endif
#if YYDEBUG
#include <stdio.h>
#endif

/* define the initial stack-sizes */
#ifdef YYSTACKSIZE
#undef YYMAXDEPTH
#define YYMAXDEPTH  YYSTACKSIZE
#else
#ifdef YYMAXDEPTH
#define YYSTACKSIZE YYMAXDEPTH
#else
#define YYSTACKSIZE 10000
#define YYMAXDEPTH  10000
#endif
#endif

#define YYINITSTACKSIZE 500

int      yydebug;
int      yynerrs;
int      yyerrflag;
int      yychar;
short   *yyssp;
YYSTYPE *yyvsp;
YYSTYPE  yyval;
//YYSTYPE  yylval;

/* variables for the parser stack */
static short   *yyss;
static short   *yysslim;
static YYSTYPE *yyvs;
static int      yystacksize;
/* allocate initial stack or double stack size, up to YYMAXDEPTH */
static int yygrowstack(void)
{
    int newsize, i;
    short *newss;
    YYSTYPE *newvs;

    if ((newsize = yystacksize) == 0)
        newsize = YYINITSTACKSIZE;
    else if (newsize >= YYMAXDEPTH)
        return -1;
    else if ((newsize *= 2) > YYMAXDEPTH)
        newsize = YYMAXDEPTH;

    i = yyssp - yyss;
    newss = (yyss != 0)
          ? (short *)realloc(yyss, newsize * sizeof(*newss))
          : (short *)malloc(newsize * sizeof(*newss));
    if (newss == 0)
        return -1;

    yyss  = newss;
    yyssp = newss + i;
    newvs = (yyvs != 0)
          ? (YYSTYPE *)realloc(yyvs, newsize * sizeof(*newvs))
          : (YYSTYPE *)malloc(newsize * sizeof(*newvs));
    if (newvs == 0)
        return -1;

    yyvs = newvs;
    yyvsp = newvs + i;
    yystacksize = newsize;
    yysslim = yyss + newsize - 1;
    return 0;
}

#define YYABORT goto yyabort
#define YYREJECT goto yyabort
#define YYACCEPT goto yyaccept
#define YYERROR goto yyerrlab
int
yyparse(void)
{
    register int yym, yyn, yystate;
#if YYDEBUG
    register const char *yys;

    if ((yys = getenv("YYDEBUG")) != 0)
    {
        yyn = *yys;
        if (yyn >= '0' && yyn <= '9')
            yydebug = yyn - '0';
    }
#endif

    yynerrs = 0;
    yyerrflag = 0;
    yychar = YYEMPTY;

    if (yyss == NULL && yygrowstack()) goto yyoverflow;
    yyssp = yyss;
    yyvsp = yyvs;
    *yyssp = yystate = 0;

yyloop:
    if ((yyn = yydefred[yystate]) != 0) goto yyreduce;
    if (yychar < 0)
    {
        if ((yychar = yylex()) < 0) yychar = 0;
#if YYDEBUG
        if (yydebug)
        {
            yys = 0;
            if (yychar <= YYMAXTOKEN) yys = yyname[yychar];
            if (!yys) yys = "illegal-symbol";
            printf("%sdebug: state %d, reading %d (%s)\n",
                    YYPREFIX, yystate, yychar, yys);
        }
#endif
    }
    if ((yyn = yysindex[yystate]) && (yyn += yychar) >= 0 &&
            yyn <= YYTABLESIZE && yycheck[yyn] == yychar)
    {
#if YYDEBUG
        if (yydebug)
            printf("%sdebug: state %d, shifting to state %d\n",
                    YYPREFIX, yystate, yytable[yyn]);
#endif
        if (yyssp >= yysslim && yygrowstack())
        {
            goto yyoverflow;
        }
        *++yyssp = yystate = yytable[yyn];
        *++yyvsp = yylval;
        yychar = YYEMPTY;
        if (yyerrflag > 0)  --yyerrflag;
        goto yyloop;
    }
    if ((yyn = yyrindex[yystate]) && (yyn += yychar) >= 0 &&
            yyn <= YYTABLESIZE && yycheck[yyn] == yychar)
    {
        yyn = yytable[yyn];
        goto yyreduce;
    }
    if (yyerrflag) goto yyinrecovery;

    yyerror("syntax error");

#ifdef lint
    goto yyerrlab;
#endif

yyerrlab:
    ++yynerrs;

yyinrecovery:
    if (yyerrflag < 3)
    {
        yyerrflag = 3;
        for (;;)
        {
            if ((yyn = yysindex[*yyssp]) && (yyn += YYERRCODE) >= 0 &&
                    yyn <= YYTABLESIZE && yycheck[yyn] == YYERRCODE)
            {
#if YYDEBUG
                if (yydebug)
                    printf("%sdebug: state %d, error recovery shifting\
 to state %d\n", YYPREFIX, *yyssp, yytable[yyn]);
#endif
                if (yyssp >= yysslim && yygrowstack())
                {
                    goto yyoverflow;
                }
                *++yyssp = yystate = yytable[yyn];
                *++yyvsp = yylval;
                goto yyloop;
            }
            else
            {
#if YYDEBUG
                if (yydebug)
                    printf("%sdebug: error recovery discarding state %d\n",
                            YYPREFIX, *yyssp);
#endif
                if (yyssp <= yyss) goto yyabort;
                --yyssp;
                --yyvsp;
            }
        }
    }
    else
    {
        if (yychar == 0) goto yyabort;
#if YYDEBUG
        if (yydebug)
        {
            yys = 0;
            if (yychar <= YYMAXTOKEN) yys = yyname[yychar];
            if (!yys) yys = "illegal-symbol";
            printf("%sdebug: state %d, error recovery discards token %d (%s)\n",
                    YYPREFIX, yystate, yychar, yys);
        }
#endif
        yychar = YYEMPTY;
        goto yyloop;
    }

yyreduce:
#if YYDEBUG
    if (yydebug)
        printf("%sdebug: state %d, reducing by rule %d (%s)\n",
                YYPREFIX, yystate, yyn, yyrule[yyn]);
#endif
    yym = yylen[yyn];
    if (yym)
        yyval = yyvsp[1-yym];
    else
        memset(&yyval, 0, sizeof yyval);
    switch (yyn)
    {
case 11:
#line 80 "sql.y"
{access_info.operation_type=6;}
break;
case 35:
#line 120 "sql.y"
{access_info.operation_type=6;}
break;
case 48:
#line 148 "sql.y"
{access_info.operation_type=1;}
break;
case 49:
#line 149 "sql.y"
{access_info.operation_type=2;}
break;
case 50:
#line 150 "sql.y"
{access_info.operation_type=4;}
break;
case 51:
#line 151 "sql.y"
{access_info.operation_type=3;}
break;
case 83:
#line 215 "sql.y"
{access_info.operation_type=4;}
break;
case 84:
#line 218 "sql.y"
{access_info.operation_type=4;}
break;
case 86:
#line 224 "sql.y"
{access_info.operation_type=2;}
break;
case 95:
#line 245 "sql.y"
{access_info.operation_type=1;}
break;
case 96:
#line 249 "sql.y"
{access_info.operation_type=1;}
break;
case 100:
#line 257 "sql.y"
{access_info.operation_type=3;}
break;
case 106:
#line 268 "sql.y"
{access_info.operation_type=3;}
break;
case 109:
#line 275 "sql.y"
{access_info.operation_type=6;}
break;
case 110:
#line 276 "sql.y"
{access_info.operation_type=8;}
break;
case 111:
#line 277 "sql.y"
{access_info.operation_type=8;}
break;
case 112:
#line 278 "sql.y"
{access_info.operation_type=7;}
break;
case 129:
#line 311 "sql.y"
{access_info.operation_type=1;}
break;
case 138:
#line 342 "sql.y"
{access_info.if_where=1;}
break;
case 147:
#line 364 "sql.y"
{access_info.line_limit[0]=0; access_info.line_limit[1]=yyvsp[0].intval;}
break;
case 148:
#line 365 "sql.y"
{access_info.line_limit[0]=yyvsp[-2].intval; access_info.line_limit[1]=yyvsp[0].intval;}
break;
case 182:
#line 439 "sql.y"
{access_info.operation_type=1;}
break;
case 208:
#line 490 "sql.y"
{char *p=malloc(yyvsp[0].strval.len+1);snprintf(p, yyvsp[0].strval.len+1, "%s", yyvsp[0].strval.strp); access_info.tbname_array[access_info.tbname_num++]=p;}
break;
case 209:
#line 491 "sql.y"
{char *p=malloc(yyvsp[0].strval.len+1);snprintf(p, yyvsp[0].strval.len+1, "%s", yyvsp[0].strval.strp); access_info.tbname_array[access_info.tbname_num++]=p;}
break;
case 210:
#line 494 "sql.y"
{snprintf(access_info.dbname, yyvsp[0].strval.len, "%s", yyvsp[0].strval.strp);}
break;
#line 1176 "y.tab.c"
    }
    yyssp -= yym;
    yystate = *yyssp;
    yyvsp -= yym;
    yym = yylhs[yyn];
    if (yystate == 0 && yym == 0)
    {
#if YYDEBUG
        if (yydebug)
            printf("%sdebug: after reduction, shifting from state 0 to\
 state %d\n", YYPREFIX, YYFINAL);
#endif
        yystate = YYFINAL;
        *++yyssp = YYFINAL;
        *++yyvsp = yyval;
        if (yychar < 0)
        {
            if ((yychar = yylex()) < 0) yychar = 0;
#if YYDEBUG
            if (yydebug)
            {
                yys = 0;
                if (yychar <= YYMAXTOKEN) yys = yyname[yychar];
                if (!yys) yys = "illegal-symbol";
                printf("%sdebug: state %d, reading %d (%s)\n",
                        YYPREFIX, YYFINAL, yychar, yys);
            }
#endif
        }
        if (yychar == 0) goto yyaccept;
        goto yyloop;
    }
    if ((yyn = yygindex[yym]) && (yyn += yystate) >= 0 &&
            yyn <= YYTABLESIZE && yycheck[yyn] == yystate)
        yystate = yytable[yyn];
    else
        yystate = yydgoto[yym];
#if YYDEBUG
    if (yydebug)
        printf("%sdebug: after reduction, shifting from state %d \
to state %d\n", YYPREFIX, *yyssp, yystate);
#endif
    if (yyssp >= yysslim && yygrowstack())
    {
        goto yyoverflow;
    }
    *++yyssp = yystate;
    *++yyvsp = yyval;
    goto yyloop;

yyoverflow:
    yyerror("yacc stack overflow");

yyabort:
    return (1);

yyaccept:
    return (0);
}
