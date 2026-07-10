<?php
/*
Plugin Name: SiteGuard WP Plugin
Plugin URI: https://www.jp-secure.com/siteguard_wp_plugin_en/
Description: Adds WordPress login and admin protections, including CAPTCHA, login lock, login alerts, renamed login URLs, and SiteGuard WAF tuning support.
Author: JP-Secure
Author URI: https://www.eg-secure.co.jp/
Text Domain: siteguard
Domain Path: /languages/
Version: 1.8.7
*/

/*
	Copyright 2014 EG Secure Solutions Inc (JP-Secure Inc)

	This program is free software; you can redistribute it and/or modify
	it under the terms of the GNU General Public License, version 2, as
	published by the Free Software Foundation.

	This program is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.

	You should have received a copy of the GNU General Public License
	along with this program; if not, write to the Free Software
	Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
*/

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

$data = get_file_data( __FILE__, array( 'version' => 'Version' ) );
define( 'SITEGUARD_VERSION', $data['version'] );

define( 'SITEGUARD_PATH', plugin_dir_path( __FILE__ ) );
define( 'SITEGUARD_URL_PATH', plugin_dir_url( __FILE__ ) );

define( 'SITEGUARD_RENAME_MODE_HTACCESS', '0');
define( 'SITEGUARD_RENAME_MODE_STUB', '1');

define( 'SITEGUARD_LOGIN_NOSELECT', 4 );
define( 'SITEGUARD_LOGIN_SUCCESS', 0 );
define( 'SITEGUARD_LOGIN_FAILED', 1 );
define( 'SITEGUARD_LOGIN_FAIL_ONCE', 2 );
define( 'SITEGUARD_LOGIN_LOCKED', 3 );

define( 'SITEGUARD_LOGIN_TYPE_NOSELECT', 2 );
define( 'SITEGUARD_LOGIN_TYPE_NORMAL', 0 );
define( 'SITEGUARD_LOGIN_TYPE_XMLRPC', 1 );

require_once 'classes/siteguard-base.php';
require_once 'classes/siteguard-config.php';
require_once 'classes/siteguard-htaccess.php';
require_once 'classes/siteguard-admin-filter.php';
require_once 'classes/siteguard-rename-login.php';
require_once 'classes/siteguard-login-history.php';
require_once 'classes/siteguard-login-lock.php';
require_once 'classes/siteguard-login-alert.php';
require_once 'classes/siteguard-captcha.php';
require_once 'classes/siteguard-disable-xmlrpc.php';
require_once 'classes/siteguard-disable-pingback.php';
require_once 'classes/siteguard-disable-author-query.php';
require_once 'classes/siteguard-waf-exclude-rule.php';
require_once 'classes/siteguard-updates-notify.php';
require_once 'admin/siteguard-menu-init.php';

global $siteguard_htaccess;
global $siteguard_config;
global $siteguard_admin_filter;
global $siteguard_rename_login;
global $siteguard_loginlock;
global $siteguard_loginalert;
global $siteguard_captcha;
global $siteguard_login_history;
global $siteguard_xmlrpc;
global $siteguard_pingback;
global $siteguard_author_query;
global $siteguard_waf_exclude_rule;
global $siteguard_updates_notify;

$siteguard_htaccess         = new SiteGuard_Htaccess();
$siteguard_config           = new SiteGuard_Config();
$siteguard_admin_filter     = new SiteGuard_AdminFilter();
$siteguard_rename_login     = new SiteGuard_RenameLogin();
$siteguard_loginlock        = new SiteGuard_LoginLock();
$siteguard_loginalert       = new SiteGuard_LoginAlert();
$siteguard_login_history    = new SiteGuard_LoginHistory();
$siteguard_captcha          = new SiteGuard_CAPTCHA();
$siteguard_xmlrpc           = new SiteGuard_Disable_XMLRPC();
$siteguard_pingback         = new SiteGuard_Disable_Pingback();
$siteguard_author_query     = new SiteGuard_Disable_Author_Query();
$siteguard_waf_exclude_rule = new SiteGuard_WAF_Exclude_Rule();
$siteguard_updates_notify   = new SiteGuard_UpdatesNotify();

function siteguard_activate() {
	global $siteguard_config, $siteguard_admin_filter, $siteguard_rename_login, $siteguard_login_history, $siteguard_captcha, $siteguard_loginlock, $siteguard_loginalert, $siteguard_xmlrpc, $siteguard_pingback, $siteguard_author_query, $siteguard_waf_exclude_rule, $siteguard_updates_notify;

	load_plugin_textdomain(
		'siteguard',
		false,
		dirname( plugin_basename( __FILE__ ) ) . '/languages'
	);

	$siteguard_config->set( 'show_admin_notices', '0' );
	$siteguard_config->update();
	$siteguard_admin_filter->init();
	$siteguard_rename_login->init();
	$siteguard_login_history->init();
	$siteguard_captcha->init();
	$siteguard_loginlock->init();
	$siteguard_loginalert->init();
	$siteguard_xmlrpc->init();
	$siteguard_pingback->init();
	$siteguard_author_query->init();
	$siteguard_waf_exclude_rule->init();
	$siteguard_updates_notify->init();
}
register_activation_hook( __FILE__, 'siteguard_activate' );

function siteguard_deactivate() {
	global $siteguard_config;
	$siteguard_config->set( 'show_admin_notices', '0' );
	$siteguard_config->update();
	SiteGuard_RenameLogin::feature_off();
	SiteGuard_AdminFilter::feature_off();
	SiteGuard_Disable_XMLRPC::feature_off();
	SiteGuard_WAF_Exclude_Rule::feature_off();
	SiteGuard_UpdatesNotify::feature_off();
}
register_deactivation_hook( __FILE__, 'siteguard_deactivate' );


class SiteGuard extends SiteGuard_Base {
	protected $menu_init;
	function __construct() {
		global $siteguard_config;
		add_action( 'plugins_loaded', array( $this, 'plugins_loaded' ) );
		$this->htaccess_check();
		// upgrade() must run on every request, not only admin_init, so that
		// upgrades from 1.7.x can clean up legacy .htaccess blocks even when
		// /wp-admin/ would otherwise be locked out by those very rules.
		add_action( 'init', array( $this, 'upgrade' ), 0 );
		if ( is_admin() ) {
			include 'admin/siteguard-menu-login-history.php';
			$this->menu_init = new SiteGuard_Menu_Init();
			add_action( 'init', array( $this, 'set_cookie' ) );
			if ( '0' === $siteguard_config->get( 'show_admin_notices' ) && '1' === $siteguard_config->get( 'renamelogin_enable' ) ) {
				add_action( 'admin_notices', array( $this, 'admin_notices' ) );
				$siteguard_config->set( 'show_admin_notices', '1' );
				$siteguard_config->update();
			}
		}
	}
	function set_cookie() {
		SiteGuard_Menu_Login_History::set_cookie();
	}
	function plugins_loaded() {
		load_plugin_textdomain(
			'siteguard',
			false,
			dirname( plugin_basename( __FILE__ ) ) . '/languages'
		);
	}
	function htaccess_check() {
		global $siteguard_config;

		// Only check whether the SiteGuard marker block still exists in .htaccess.
		// The actual ".htaccess effectiveness" probe (test_htaccess) is performed
		// only when the user toggles a feature on, to avoid loopback HTTP
		// requests on every WordPress request.
		if ( '1' === $siteguard_config->get( 'waf_exclude_rule_enable' ) ) {
			if ( ! SiteGuard_Htaccess::is_exists_setting( SiteGuard_WAF_Exclude_Rule::get_mark() ) ) {
				$siteguard_config->set( 'waf_exclude_rule_enable', '0' );
				$siteguard_config->update();
			}
		}
		if ( '1' === $siteguard_config->get( 'renamelogin_enable' ) ) {
			if ( SITEGUARD_RENAME_MODE_HTACCESS === $siteguard_config->get( 'renamelogin_stub' ) ) {
				if ( ! SiteGuard_Htaccess::is_exists_setting( SiteGuard_RenameLogin::get_mark() ) ) {
					$siteguard_config->set( 'renamelogin_enable', '0' );
					$siteguard_config->update();
				}
			}
		}
	}
	function admin_notices() {
		global $siteguard_rename_login;
		echo '<div class="updated" style="background-color:#719f1d;"><p><span style="border: 4px solid #def1b8;padding: 4px 4px;color:#fff;font-weight:bold;background-color:#038bc3;">';
		echo esc_html__( 'The login page URL has been changed.', 'siteguard' ) . '</span>';
		printf(
			'<span style="color:#eee;">'
			. esc_html__( 'Please bookmark the %1$s. You can change this setting %2$s.', 'siteguard' )
			. '</span></p></div>',
			'<a style="color:#fff;text-decoration:underline;" href="' . esc_url( wp_login_url() ) . '">' . esc_html__( 'new login URL', 'siteguard' ) . '</a>',
			'<a style="color:#fff;text-decoration:underline;" href="' . esc_url( menu_page_url( 'siteguard_rename_login', false ) ) . '">' . esc_html__( 'here', 'siteguard' ) . '</a>'
		);
		$siteguard_rename_login->send_notify();
	}
	function upgrade() {
		global $siteguard_config, $siteguard_rename_login, $siteguard_admin_filter, $siteguard_loginalert, $siteguard_updates_notify, $siteguard_login_history, $siteguard_xmlrpc, $siteguard_author_query, $siteguard_waf_exclude_rule;
		$upgrade_ok  = true;
		$old_version = $siteguard_config->get( 'version' );
		if ( '' === $old_version ) {
			$old_version = '0.0.0';
		}
		if ( $old_version === SITEGUARD_VERSION ) {
			return;
		}
		if ( version_compare( $old_version, '1.0.6' ) < 0 ) {
			if ( '1' === $siteguard_config->get( 'admin_filter_enable' ) ) {
				if ( true !== $siteguard_admin_filter->feature_on( $this->get_ip() ) ) {
					siteguard_error_log( 'Failed to update at admin_filter from ' . $old_version . ' to ' . SITEGUARD_VERSION . '.' );
					$upgrade_ok = false;
				}
			}
		}
		if ( version_compare( $old_version, '1.1.1' ) < 0 ) {
			$siteguard_loginalert->init();
		}
		if ( version_compare( $old_version, '1.2.0' ) < 0 ) {
			$siteguard_updates_notify->init();
		}
		if ( version_compare( $old_version, '1.2.5' ) < 0 ) {
			if ( '1' === $siteguard_config->get( 'admin_filter_enable' ) ) {
				$siteguard_admin_filter->cvt_status_for_1_2_5( $this->get_ip() );
			}
			if ( '1' === $siteguard_config->get( 'renamelogin_enable' ) ) {
				if ( true !== $siteguard_rename_login->feature_on() ) {
					siteguard_error_log( 'Failed to update at rename_login from ' . $old_version . ' to ' . SITEGUARD_VERSION . '.' );
					$upgrade_ok = false;
				}
			}
		}
		if ( version_compare( $old_version, '1.3.0' ) < 0 ) {
			$siteguard_login_history->init();
			$siteguard_xmlrpc->init();
		}
		if ( version_compare( $old_version, '1.5.0' ) < 0 ) {
			$admin_filter_exclude_path = $siteguard_config->get( 'admin_filter_exclude_path' );
			if ( false === strpos( $admin_filter_exclude_path, 'site-health.php' ) ) {
				$admin_filter_exclude_path .= ', site-health.php';
				$siteguard_config->set( 'admin_filter_exclude_path', $admin_filter_exclude_path );
				$siteguard_config->update();
			}
		}
		if ( version_compare( $old_version, '1.5.1' ) < 0 ) {
			if ( '1' === $siteguard_config->get( 'admin_filter_enable' ) ) {
				if ( true !== $siteguard_admin_filter->feature_on( $this->get_ip() ) ) {
					siteguard_error_log( 'Failed to update at admin_filter from ' . $old_version . ' to ' . SITEGUARD_VERSION . '.' );
					$upgrade_ok = false;
				}
			}
			if ( '1' === $siteguard_config->get( 'disable_xmlrpc_enable' ) ) {
				if ( true !== $siteguard_xmlrpc->feature_on() ) {
					siteguard_error_log( 'Failed to update at disable_xmlrpc from ' . $old_version . ' to ' . SITEGUARD_VERSION . '.' );
					$upgrade_ok = false;
				}
			}
		}
		if ( version_compare( $old_version, '1.6.0' ) < 0 ) {
			$siteguard_author_query->init();
		}
		if ( version_compare( $old_version, '1.7.0' ) < 0 ) {
			if ( '1' === $siteguard_config->get( 'admin_filter_enable' ) ) {
				if ( true !== $siteguard_admin_filter->feature_on( $this->get_ip() ) ) {
					siteguard_error_log( 'Failed to update at admin_filter from ' . $old_version . ' to ' . SITEGUARD_VERSION . '.' );
					$upgrade_ok = false;
				}
			}
		}
		if ( version_compare( $old_version, '1.8.0' ) < 0 ) {
			// Legacy Nginx-exposure cleanup and the rescue_enable default. These
			// are unrelated to the /wp-admin/ lockout and ran when the install
			// first reached 1.8.0, so they stay gated on < 1.8.0. The Admin
			// Filter / XML-RPC .htaccess blocks (which cause the lockout) are
			// cleared in the < 1.8.3 block below.
			if ( '' === $siteguard_config->get( 'rescue_enable' ) ) {
				$siteguard_config->set( 'rescue_enable', '1' );
				$siteguard_config->update();
			}
			// Remove legacy error.log left by previous versions; logging now
			// uses PHP error_log() so the file would only sit web-exposed on Nginx.
			$legacy_log = SITEGUARD_PATH . 'error.log';
			if ( file_exists( $legacy_log ) ) {
				@unlink( $legacy_log );
			}
			// Remove legacy plugin-directory tmp/ used for .htaccess rebuilds.
			// `clear_settings()` / `update_settings()` now short-circuit on
			// Nginx (no .htaccess in use), so this directory will not be
			// recreated there. On Apache it will be regenerated as needed
			// by make_tmp_dir(). Existing orphan tempnam files would be
			// web-exposed on Nginx without the .htaccess inside the dir.
			$legacy_tmp = SITEGUARD_PATH . 'tmp';
			if ( is_dir( $legacy_tmp ) ) {
				$entries = @scandir( $legacy_tmp );
				if ( is_array( $entries ) ) {
					foreach ( $entries as $entry ) {
						if ( '.' === $entry || '..' === $entry ) {
							continue;
						}
						$path = $legacy_tmp . DIRECTORY_SEPARATOR . $entry;
						if ( is_file( $path ) ) {
							if ( ! @unlink( $path ) ) {
								@chmod( $path, 0644 );
								@unlink( $path );
							}
						}
					}
				}
				@rmdir( $legacy_tmp );
			}
			// Remove legacy CAPTCHA answer files (*.txt). Pre-1.8.0 stored
			// them at WP_CONTENT_DIR/siteguard/ with an .htaccess block on
			// .txt; on Nginx that block does not apply and the salt+hash
			// would be readable. New answer files use .php with a stub
			// prefix and live in the same directory.
			$captcha_dir = path_join( WP_CONTENT_DIR, 'siteguard' );
			if ( is_dir( $captcha_dir ) ) {
				$entries = @scandir( $captcha_dir );
				if ( is_array( $entries ) ) {
					foreach ( $entries as $entry ) {
						if ( preg_match( '/\.txt$/', $entry ) ) {
							$path = $captcha_dir . DIRECTORY_SEPARATOR . $entry;
							if ( is_file( $path ) ) {
								if ( ! @unlink( $path ) ) {
									@chmod( $path, 0644 );
									@unlink( $path );
								}
							}
						}
					}
				}
			}
		}
		if ( version_compare( $old_version, '1.8.3' ) < 0 ) {
			// Admin Page IP Filter and XML-RPC protection moved from .htaccess
			// to PHP in 1.8.x, leaving their 1.7.x .htaccess blocks orphaned.
			// The Admin Filter block ("RewriteRule ^wp-admin 404-siteguard")
			// blocks /wp-admin/ at the Apache layer and can lock administrators
			// out. clear_settings() is idempotent (a no-op when the mark is
			// absent), so gate this on the fix release (< 1.8.3) rather than
			// < 1.8.0: that also recovers the rare install whose stored version
			// already advanced past 1.8.0 while the block survived (e.g. the
			// .htaccess was briefly unwritable during the 1.8.0 upgrade).
			//
			// Rename Login and WAF Tuning Support still use .htaccess in 1.8.x
			// with the same mark and block format as 1.7.x, so their blocks are
			// the current, valid mechanism — they are intentionally NOT touched
			// here (clearing WAF without a rebuild would drop working rules).
			SiteGuard_Htaccess::clear_settings( $siteguard_admin_filter->get_mark() );
			SiteGuard_Htaccess::clear_settings( $siteguard_xmlrpc->get_mark() );
		}
		if ( $upgrade_ok && SITEGUARD_VERSION !== $old_version ) {
			$siteguard_config->set( 'version', SITEGUARD_VERSION );
			$siteguard_config->update();
		}
	}
}
$siteguard = new SiteGuard();
