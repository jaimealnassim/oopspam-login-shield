<?php
/**
 * Uninstall: clean up plugin options and drop the LLA log table.
 *
 * @package OOPSpam_Login_Shield
 */

if ( ! defined( 'WP_UNINSTALL_PLUGIN' ) ) {
	exit;
}

/**
 * Drop the LLA log table for the current site.
 */
function oopspam_ls_uninstall_drop_table() {
	global $wpdb;
	// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery.SchemaChange
	$wpdb->query( 'DROP TABLE IF EXISTS ' . $wpdb->prefix . 'oopspam_ls_log' );
}

/**
 * Delete plugin options for the current site.
 */
function oopspam_ls_uninstall_delete_options() {
	delete_option( 'oopspam_ls_settings' );
	delete_option( 'oopspam_ls_secret' );
	delete_option( 'oopspam_ls_db_version' );
	delete_option( 'oopspam_ls_lockouts' );
	delete_option( 'oopspam_ls_db_install_failed' );
}

oopspam_ls_uninstall_delete_options();
oopspam_ls_uninstall_drop_table();

// Clear our cron schedule for good measure.
wp_clear_scheduled_hook( 'oopspam_ls_lla_cleanup' );

// Multisite: repeat per site.
if ( is_multisite() ) {
	$sites = function_exists( 'get_sites' ) ? get_sites( array( 'fields' => 'ids' ) ) : array();
	foreach ( $sites as $site_id ) {
		switch_to_blog( $site_id );
		oopspam_ls_uninstall_delete_options();
		oopspam_ls_uninstall_drop_table();
		restore_current_blog();
	}
}
