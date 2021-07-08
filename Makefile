start: ## Start the devstack
	docker-compose up -d

stop: ## Stop the devstack
	docker-compose stop

destroy: ## Remove all containers and volumes
	docker-compose down -v

test: ## Run tests
	docker exec -e COLUMNS="`tput cols`" -e LINES="`tput lines`" -it cert-manager.devstack.test /bin/bash /opt/scripts/run_tests.sh
