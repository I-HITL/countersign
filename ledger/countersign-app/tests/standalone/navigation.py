"""Device-specific navigation. The enrollment prompt is an NBGL choice; the
review uses Ragger's scenario navigator, told that the last page carries the
app's own title ("Approve request?") on Nano devices, where Ragger otherwise
expects the SDK default "Sign operation"."""

from ragger.navigator import NavInsID, Navigator
from ragger.navigator.navigation_scenario import NavigateWithScenario


def approve_request(scenario_navigator: NavigateWithScenario, device) -> None:
    if device.is_nano:
        scenario_navigator.review_approve(custom_screen_text=r"^Approve request\?$", do_comparison=False)
    else:
        scenario_navigator.review_approve(do_comparison=False)


def reject_request(scenario_navigator: NavigateWithScenario) -> None:
    scenario_navigator.review_reject(do_comparison=False)


def confirm_enrollment(navigator: Navigator, device) -> None:
    if device.touchable:
        navigator.navigate([NavInsID.USE_CASE_CHOICE_CONFIRM, NavInsID.USE_CASE_STATUS_DISMISS],
                           screen_change_before_first_instruction=True)
    else:
        navigator.navigate_until_text(NavInsID.RIGHT_CLICK, [NavInsID.BOTH_CLICK], "^Confirm enrollment$",
                                      screen_change_after_last_instruction=False)


def cancel_enrollment(navigator: Navigator, device) -> None:
    if device.touchable:
        navigator.navigate([NavInsID.USE_CASE_CHOICE_REJECT, NavInsID.USE_CASE_STATUS_DISMISS],
                           screen_change_before_first_instruction=True)
    else:
        navigator.navigate_until_text(NavInsID.RIGHT_CLICK, [NavInsID.BOTH_CLICK], "^Cancel$",
                                      screen_change_after_last_instruction=False)
