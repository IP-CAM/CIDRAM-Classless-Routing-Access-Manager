<?php
/**
 * This file is a part of the CIDRAM package.
 * Homepage: https://cidram.github.io/
 *
 * CIDRAM COPYRIGHT 2016 and beyond by Caleb Mazalevskis (Maikuolan).
 *
 * License: GNU/GPLv2
 * @see LICENSE.txt
 *
 * This file: Report orchestrator (last modified: 2024.09.12).
 */

namespace CIDRAM\CIDRAM;

class Reporter
{
    /**
     * @var array An array of handlers to use for processing reports.
     */
    private $Handlers = [];

    /**
     * @var array An array of reports to process.
     */
    private $Reports = [];

    /**
     * @var \Maikuolan\Common\Events Needed for logging.
     */
    private $Events;

    /**
     * Construct the report orchestrator.
     *
     * @param \Maikuolan\Common\Events $Events Needed for logging.
     * @return void
     */
    public function __construct(\Maikuolan\Common\Events &$Events)
    {
        $this->Events = &$Events;
    }

    /**
     * Adds a new report handler.
     *
     * @param callable $Handler The handler to add.
     * @return void
     */
    public function addHandler(callable $Handler): void
    {
        $this->Handlers[] = $Handler;
    }

    /**
     * Adds data to the current report and pushes the queue forward if needed.
     *
     * @param int|array $Categories An ID, or an array of IDs, for the current report.
     * @param string|array $Comments A comment, or an array of comments, for the current report.
     * @param string $IP The IP address associated with the current report.
     * @return void
     */
    public function report($Categories, $Comments, string $IP): void
    {
        if (!isset($this->Reports[$IP])) {
            $this->Reports[$IP] = ['Categories' => [], 'Comments' => [], 'IP' => $IP];
        }
        if (!is_array($Categories)) {
            $Categories = [$Categories];
        }
        foreach ($Categories as $Category) {
            $this->Reports[$IP]['Categories'][] = $Category;
        }
        if (!is_array($Comments)) {
            $Comments = [$Comments];
        }
        foreach ($Comments as $Comment) {
            if (!is_string($Comment) || $Comment === '') {
                continue;
            }
            $this->Reports[$IP]['Comments'][] = $Comment;
        }
    }

    /**
     * Count reports.
     *
     * @return int The number of reports in the queue.
     */
    public function count(): int
    {
        return count($this->Reports);
    }

    /**
     * Process all reports.
     *
     * @return void
     */
    public function process(): void
    {
        /** Iterate through handlers. */
        foreach ($this->Handlers as $Handler) {
            $DateTime = date('c', time());

            /** Iterate through queued reports. */
            foreach ($this->Reports as $Report) {
                /** Guard. */
                if (count($Report['Categories']) === 0 || count($Report['Comments']) === 0 || $Report['IP'] === '') {
                    continue;
                }

                /** Don't duplicate categories. */
                $Report['Categories'] = array_unique($Report['Categories'], SORT_NUMERIC);

                /** Prepare comments. */
                $Report['Comments'] = sprintf('Automated report (%s). %s', $DateTime, implode(' ', $Report['Comments']));

                /** Call handler. */
                $Handler($Report, $DateTime);
            }
        }

        /** Report logging. */
        if ($this->Events->assigned('writeToReportLog')) {
            foreach ($this->Reports as $Report) {
                /** Guard. */
                if (count($Report['Comments']) === 0 || $Report['IP'] === '') {
                    continue;
                }

                /** Fire the logger. */
                $this->Events->fireEvent('writeToReportLog', implode(' ', $Report['Comments']), $Report['IP']);
            }
        }

        /** Flush old reports. */
        $this->Reports = [];
    }
}
