//! `https://didcomm.org/push-notifications-fcm/1.0/*` message catalogue.
//! Implements the DIDComm push-notifications FCM messages per RFC 0734.

mod delete_device_info;
mod get_device_info;
mod problem_report;
mod set_device_info;

pub use delete_device_info::{DeleteDeviceInfoMessage, DELETE_DEVICE_INFO_TYPE};
pub use get_device_info::{
    DeviceInfoMessage, GetDeviceInfoMessage, DEVICE_INFO_TYPE, GET_DEVICE_INFO_TYPE,
};
pub use problem_report::{ProblemDescription, ProblemReportMessage, PROBLEM_REPORT_TYPE};
pub use set_device_info::{SetDeviceInfoMessage, SET_DEVICE_INFO_TYPE};
