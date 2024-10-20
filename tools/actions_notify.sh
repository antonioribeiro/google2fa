#!/usr/bin/env bash

. "$(dirname -- "$0")/../tools/helpers.sh"

notify_about_actions_required() {
    CHANGED_FILES="$(git diff-tree -r --name-status --no-commit-id $1 $2)"

    is_changed() {
        echo "$CHANGED_FILES" | grep -Eq "$1"
    }

    is_added() {
        echo "$CHANGED_FILES" | grep -Eq "^A\s+$1"
    }

    is_modified() {
         echo "$CHANGED_FILES" | grep -Eq "^M\s+$1"
    }

    is_deleted() {
         echo "$CHANGED_FILES" | grep -Eq "^D\s+$1"
    }

    print_notification() {
        filename="$1"
        shift
        action="$@"
        echo -e "${YELLOW}${filename}${NC} changed. Please run ${CYAN}${action}${NC}"
    }

    is_changed composer.lock && print_notification "composer.lock" "composer install"

    is_changed package-lock.json && print_notification "package-lock.json" "npm install"

    is_changed ^database/seeders && print_notification "Seeders" "php artisan db:seed"

    if is_deleted database/migrations; then
        echo -e "${YELLOW}Migration files${NC} ${RED}removed${NC}. Consider going back to the previous branch to rollback changes with ${CYAN}php artisan migrate:rollback${NC}"
    fi

    if is_modified database/migrations; then
        echo -e "${YELLOW}Migration files${NC} ${MAGENTA}modified${NC}. Consider running ${CYAN}php artisan migrate:rollback && php artisan migrate${NC}"
    fi

    if is_added database/migrations; then
        echo -e "${YELLOW}Migration files${NC} ${GREEN}added${NC}. Please run ${CYAN}php artisan migrate${NC}"
    fi
}
