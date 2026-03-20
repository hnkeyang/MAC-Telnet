/*
    Mac-Telnet - Connect to RouterOS or mactelnetd devices via MAC address
    Copyright (C) 2010, Håkon Nessjøen <haakon.nessjoen@gmail.com>

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License along
    with this program; if not, write to the Free Software Foundation, Inc.,
    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include <pwd.h>
#include <security/pam_appl.h>
#include "users.h"
#include "config.h"

/* PAM conversation structure for password authentication */
struct pam_conv_data {
	const char *password;
};

/* PAM conversation function */
static int pam_conv_func(int num_msg, const struct pam_message **msg,
                         struct pam_response **resp, void *appdata_ptr)
{
	struct pam_conv_data *data = (struct pam_conv_data *)appdata_ptr;
	struct pam_response *reply;
	int i;

	if (num_msg <= 0)
		return PAM_CONV_ERR;

	reply = calloc(num_msg, sizeof(struct pam_response));
	if (reply == NULL)
		return PAM_CONV_ERR;

	for (i = 0; i < num_msg; i++) {
		switch (msg[i]->msg_style) {
		case PAM_PROMPT_ECHO_OFF:
		case PAM_PROMPT_ECHO_ON:
			reply[i].resp = strdup(data->password);
			reply[i].resp_retcode = 0;
			break;
		case PAM_ERROR_MSG:
		case PAM_TEXT_INFO:
			reply[i].resp = NULL;
			reply[i].resp_retcode = 0;
			break;
		default:
			/* Free all responses on error */
			while (i > 0) {
				i--;
				if (reply[i].resp != NULL) {
					memset(reply[i].resp, 0, strlen(reply[i].resp));
					free(reply[i].resp);
				}
			}
			free(reply);
			return PAM_CONV_ERR;
		}
	}

	*resp = reply;
	return PAM_SUCCESS;
}

LIST_HEAD(mt_users);

void read_userfile(void)
{
	char line[BUFSIZ];
	struct mt_credentials *cred;
	FILE *file = fopen(USERSFILE, "r");

	if (file == NULL) {
		perror(USERSFILE);
		exit(1);
	}

	while (fgets(line, sizeof line, file))
	{
		char *user;
		char *password;

		user = strtok(line, ":");
		password = strtok(NULL, "\n");

		if (!user || !password || *user == '#')
			continue;

		cred = calloc(1, sizeof(*cred));

		if (!cred)
			continue;

		strncpy(cred->username, user, sizeof(cred->username) - 1);
		strncpy(cred->password, password, sizeof(cred->password) - 1);

		list_add_tail(&cred->list, &mt_users);
	}

	fclose(file);
}

struct mt_credentials* find_user(char *username)
{
	struct mt_credentials *cred;

	list_for_each_entry(cred, &mt_users, list)
		if (!strcmp(cred->username, username))
			return cred;

	return NULL;
}


void drop_privileges(char *username)
{
	struct passwd *user = (struct passwd *) getpwnam(username);
	if (user == NULL) {
		fprintf(stderr, "Failed dropping privileges. The user %s is not a valid username on local system.\n", username);
		exit(1);
	}
	if (getuid() == 0) {
		/* process is running as root, drop privileges */
		if (setgid(user->pw_gid) != 0) {
			perror("setgid: Error dropping group privileges");
		    exit(1);
		}
		if (setuid(user->pw_uid) != 0) {
			perror("setuid: Error dropping user privileges");
		    exit(1);
		}
		/* Verify if the privileges were dropped. */
		if (setuid(0) != -1) {
			perror("Failed to drop privileges");
			exit(1);
		}
	}
	else {
		fprintf(stderr, "Failed dropping privileges. Not running as privileged user.\n");
		exit(1);
	}
}

/*
 * Authenticate a user against the system using PAM
 * Returns 1 on success, 0 on failure
 */
int authenticate_system_user(const char *username, const char *password)
{
	pam_handle_t *pamh = NULL;
	struct pam_conv_data conv_data;
	struct pam_conv conv;
	int retval;
	int result = 0;

	conv_data.password = password;
	conv.conv = pam_conv_func;
	conv.appdata_ptr = &conv_data;

	/* Initialize PAM */
	retval = pam_start("mactelnet", username, &conv, &pamh);
	if (retval != PAM_SUCCESS) {
		return 0;
	}

	/* Authenticate the user */
	retval = pam_authenticate(pamh, 0);
	if (retval == PAM_SUCCESS) {
		/* Check if the account is valid */
		retval = pam_acct_mgmt(pamh, 0);
		if (retval == PAM_SUCCESS) {
			result = 1;
		}
	}

	/* Clean up PAM */
	pam_end(pamh, retval);

	return result;
}
