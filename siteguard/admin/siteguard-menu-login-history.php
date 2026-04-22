<?php

require_once 'siteguard-login-history-table.php';

class SiteGuard_Menu_Login_History extends SiteGuard_Base {
	protected $wp_list_table;
	function __construct() {
		$this->wp_list_table = new SiteGuard_LoginHistory_Table();
		$this->wp_list_table->prepare_items();
		$this->render_page();
	}
	function render_page() {
		global $siteguard_config, $siteguard_login_history;
		$img_path = SITEGUARD_URL_PATH . 'images/';
		echo '<div class="wrap">';
		echo '<img src="' . $img_path . 'sg_wp_plugin_logo_40.png" alt="SiteGuard Logo" />';
		echo '<h2>' . esc_html__( 'Login history', 'siteguard' ) . "</h2>\n";
		echo '<div class="siteguard-description">'
		. esc_html__( 'You can find docs about this function on ', 'siteguard' )
		. '<a href="' . esc_url( __( 'https://www.jp-secure.com/siteguard_wp_plugin_en/howto/login_history/', 'siteguard' ) ) . '" target="_blank">' . esc_html__( 'SiteGuard WP Plugin Page', 'siteguard' ) . '</a>' . esc_html__( '.', 'siteguard' ) . '</div>';
		$error = siteguard_check_multisite();
		if ( is_wp_error( $error ) ) {
			echo '<p class="description">';
			echo esc_html( $error->get_error_message() );
			echo '</p>';
		}
		?>
		<form name="form1" method="post" action="">
		<?php
		wp_nonce_field( 'siteguard_login_history_filter', 'siteguard_filter_nonce' );
		$this->wp_list_table->display(); ?>
		<div class="siteguard-description">
		<?php esc_html_e( 'Login history can be referenced. Let\'s see if there are any suspicious history. History, registered 10,000 maximum, will be removed from those old and more than 10,000.', 'siteguard' ); ?>
		</div>
		<input type="hidden" name="page" value="<?php echo esc_attr( $_REQUEST['page'] ); ?>">
		</form>
		</div>
		<?php
	}
	private static function set_cookie_int( $name, $value, $expire ) {
		$path     = '/';
		$secure   = is_ssl();
		$httponly = true;
		$samesite = 'Lax';

		if ( PHP_VERSION_ID >= 70300 ) {
			setcookie( $name, $value, [
				'expires'  => $expire,
				'path'	 => $path,
				'secure'   => $secure,
				'httponly' => $httponly,
				'samesite' => $samesite,
			]);
		} else {
			setcookie( $name, $value, $expire, $path . '; samesite=' . $samesite, '', $secure, $httponly );
		}
	}
	static function clear_cookie() {
		$expire = time() - 1800;
		self::set_cookie_int( 'siteguard_log_filter_operation', '', $expire );
		self::set_cookie_int( 'siteguard_log_filter_type', '', $expire );
		self::set_cookie_int( 'siteguard_log_filter_login_name', '', $expire );
		self::set_cookie_int( 'siteguard_log_filter_ip_address', '', $expire );
		self::set_cookie_int( 'siteguard_log_filter_login_name_not', '', $expire );
		self::set_cookie_int( 'siteguard_log_filter_ip_address_not', '', $expire );
	}
	static function set_cookie() {
		if ( ! isset( $_GET['page'] ) ) {
			return;
		}
		if ( 'siteguard_login_history' !== $_GET['page'] ) {
			return;
		}
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}
		if ( 'POST' !== $_SERVER['REQUEST_METHOD'] ) {
			$referer = wp_get_referer();
			if ( false === strpos( $referer, 'siteguard_login_history' ) ) {
				self::clear_cookie();
			}
			return;
		}
		if ( ! isset( $_POST['siteguard_filter_nonce'] ) || ! wp_verify_nonce( $_POST['siteguard_filter_nonce'], 'siteguard_login_history_filter' ) ) {
			return;
		}
		if ( isset( $_POST['filter_reset'] ) ) {
			self::clear_cookie();
		} else {
			$expire = time() + 3600;
			if ( isset( $_POST['filter_operation'] ) ) {
				self::set_cookie_int( 'siteguard_log_filter_operation', sanitize_text_field( $_POST['filter_operation'] ), $expire );
			}
			if ( isset( $_POST['filter_type'] ) ) {
				self::set_cookie_int( 'siteguard_log_filter_type', sanitize_text_field( $_POST['filter_type'] ), $expire );
			}
			if ( isset( $_POST['filter_login_name'] ) ) {
				self::set_cookie_int( 'siteguard_log_filter_login_name', sanitize_text_field( $_POST['filter_login_name'] ), $expire );
			}
			if ( isset( $_POST['filter_ip_address'] ) ) {
				self::set_cookie_int( 'siteguard_log_filter_ip_address', sanitize_text_field( $_POST['filter_ip_address'] ), $expire );
			}
			if ( isset( $_POST['filter_login_name_not'] ) ) {
				self::set_cookie_int( 'siteguard_log_filter_login_name_not', sanitize_text_field( $_POST['filter_login_name_not'] ), $expire );
			}
			if ( isset( $_POST['filter_ip_address_not'] ) ) {
				self::set_cookie_int( 'siteguard_log_filter_ip_address_not', sanitize_text_field( $_POST['filter_ip_address_not'] ), $expire );
			}
		}

	}
}
