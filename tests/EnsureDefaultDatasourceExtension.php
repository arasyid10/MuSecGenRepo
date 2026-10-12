<?php
declare(strict_types=1);

namespace Cake\Test;

use Cake\Datasource\ConnectionManager;
use PHPUnit\Event\Test\PreparationStarted;
use PHPUnit\Event\Test\PreparationStartedSubscriber;

final class EnsureDefaultDatasourceExtension implements PreparationStartedSubscriber
{
    public function notify(PreparationStarted $event): void
    {
        if (!ConnectionManager::getConfig('test')) {
            return;
        }

        if (!ConnectionManager::getConfig('default')) {
            ConnectionManager::setConfig('default', ConnectionManager::getConfig('test'));
        }
    }
}