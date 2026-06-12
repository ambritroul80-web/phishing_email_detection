#include <stdio.h>
#include <string.h>
#include <ctype.h>

#define MAX_LEN 5000

const char *keywords[] = {
    "verify account",
    "click here",
    "urgent",
    "free gift",
    "winner",
    "reset password",
    "account locked",
    "bank alert",
    "security alert",
    "act now",
    "limited time",
    "payment failed"
};

int keyword_count = 12;

/* Convert string to lowercase */
void toLower(char str[])
{
    int i;

    for(i = 0; str[i] != '\0'; i++)
    {
        str[i] = tolower(str[i]);
    }
}

/* Check phishing keywords */
int checkKeywords(char email[])
{
    int score = 0;
    int i;

    char temp[MAX_LEN];

    strcpy(temp, email);
    toLower(temp);

    printf("\nKeyword Analysis:\n");

    for(i = 0; i < keyword_count; i++)
    {
        if(strstr(temp, keywords[i]) != NULL)
        {
            printf("Found: %s\n", keywords[i]);
            score += 10;
        }
    }

    return score;
}

/* Check suspicious links */
int checkLinks(char email[])
{
    int score = 0;

    printf("\nURL Analysis:\n");

    if(strstr(email, "http://") != NULL)
    {
        printf("Insecure HTTP URL detected\n");
        score += 15;
    }

    if(strstr(email, "bit.ly") != NULL)
    {
        printf("Shortened URL detected\n");
        score += 20;
    }

    if(strstr(email, "tinyurl") != NULL)
    {
        printf("TinyURL detected\n");
        score += 20;
    }

    if(strstr(email, "@") != NULL)
    {
        printf("Suspicious @ symbol detected\n");
        score += 5;
    }

    return score;
}

/* Check excessive capital letters */
int checkCaps(char email[])
{
    int i;
    int caps = 0;

    for(i = 0; email[i] != '\0'; i++)
    {
        if(isupper(email[i]))
        {
            caps++;
        }
    }

    if(caps > 20)
    {
        printf("\nToo many capital letters\n");
        return 10;
    }

    return 0;
}

/* Check exclamation marks */
int checkExclamation(char email[])
{
    int i;
    int count = 0;

    for(i = 0; email[i] != '\0'; i++)
    {
        if(email[i] == '!')
        {
            count++;
        }
    }

    if(count > 3)
    {
        printf("Too many exclamation marks\n");
        return 10;
    }

    return 0;
}

/* Classification */
void classify(int score)
{
    printf("\n========================\n");
    printf("Risk Score : %d\n", score);

    if(score < 20)
    {
        printf("Classification : SAFE\n");
    }
    else if(score < 50)
    {
        printf("Classification : SUSPICIOUS\n");
    }
    else
    {
        printf("Classification : LIKELY PHISHING\n");
    }
}

/* Security advice */
void recommendations(int score)
{
    printf("\nRecommendations:\n");

    if(score < 20)
    {
        printf("- Email appears safe\n");
    }
    else if(score < 50)
    {
        printf("- Verify sender identity\n");
        printf("- Avoid unknown links\n");
    }
    else
    {
        printf("- Do not click links\n");
        printf("- Do not open attachments\n");
        printf("- Report email as phishing\n");
        printf("- Delete the email\n");
    }
}

/* Main menu */
int main()
{
    char email[MAX_LEN];

    int score = 0;

    printf("====================================\n");
    printf(" PHISHING EMAIL DETECTION SYSTEM\n");
    printf("====================================\n");

    printf("\nEnter Email Content:\n");
    fgets(email, MAX_LEN, stdin);

    score += checkKeywords(email);
    score += checkLinks(email);
    score += checkCaps(email);
    score += checkExclamation(email);

    classify(score);

    recommendations(score);

    printf("\nAnalysis Completed.\n");

    return 0;
}
