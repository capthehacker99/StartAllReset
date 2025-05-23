const std = @import("std");
const win = std.os.windows;
const DWORD = win.DWORD;
const UINT = win.UINT;

// WINAPIS
extern "kernel32" fn GetSystemFirmwareTable(FirmwareTableProviderSignature: DWORD, FirmwareTableID: DWORD, pFirmwareTableBuffer: usize, BufferSize: DWORD) callconv(win.WINAPI) UINT;
extern "advapi32" fn RegDeleteKeyA(hKey: win.HKEY, lpSubKey: win.LPCSTR) callconv(win.WINAPI) win.LSTATUS;
extern "advapi32" fn RegCreateKeyA(hKey: win.HKEY, lpSubKey: win.LPCSTR, phkResult: *win.HKEY) callconv(win.WINAPI) win.LSTATUS;
extern "advapi32" fn RegCloseKey(hKey: win.HKEY) callconv(win.WINAPI) win.LSTATUS;

fn strToU32(str: []const u8) u32 {
    var result: u32 = 0;
    for (str) |val| {
        result <<= 8;
        result |= val;
    }
    return result;
}

fn findIndexOfNull(str: []const i8) usize {
    var len: usize = 0;
    for (str) |val| {
        if (val == 0)
            break;
        len += 1;
    }
    return len;
}

fn getSecretUUID(buf: []u8) bool {
    const RSMB = comptime strToU32("RSMB");
    const defaultUUID = "yyyy yyyy}\x00";
    const sizeOfBuffer = GetSystemFirmwareTable(RSMB, 0, 0, 0);
    if (sizeOfBuffer == 0) {
        @memcpy(buf.ptr, defaultUUID);
        return false;
    }
    var buffer: [4096]i8 = undefined;
    const bytesWritten = GetSystemFirmwareTable(RSMB, 0, @intFromPtr(&buffer), sizeOfBuffer);
    if (bytesWritten == 0) {
        @memcpy(buf.ptr, defaultUUID);
        return false;
    }
    var i: usize = 0;
    while (buffer[i + 8] != 1) {
        const ch = buffer[i + 9];
        if (ch != 0) {
            var j: usize = @intCast(@as(isize, @intCast(i)) + ch);
            while (true) {
                if (j == 0)
                    break;
                const len = findIndexOfNull(buffer[@intCast(j + 8)..]);
                if (len == 0)
                    break;
                j += len + 1;
            }
            i = j + 1;
            if (i < bytesWritten)
                continue;
        }
        @memcpy(buf.ptr, defaultUUID);
        return false;
    }
    if (i == 0) {
        @memcpy(buf.ptr, defaultUUID);
        return false;
    }
    const v11 = i + 8;
    const v12 = @as([*]u8, @ptrCast(&buffer[v11 + 16]));
    const firstPart = @as([*]align(1) u32, @ptrCast(&buffer[v11 + 8]));
    const secPart = @as([*]align(1) u16, @ptrCast(&firstPart[1]));
    _ = std.fmt.bufPrint(buf, "{x:0>8}", .{firstPart[0]}) catch unreachable;
    _ = std.fmt.bufPrint(buf[9..], "{x:0>4}", .{secPart[1]}) catch unreachable;
    _ = std.fmt.bufPrint(buf[13..], "{x:0>4}", .{secPart[0]}) catch unreachable;
    _ = std.fmt.bufPrint(buf[18..], "{x:0>2}", .{v12[3]}) catch unreachable;
    _ = std.fmt.bufPrint(buf[20..], "{x:0>2}", .{v12[2]}) catch unreachable;
    _ = std.fmt.bufPrint(buf[22..], "{x:0>2}", .{v12[1]}) catch unreachable;
    _ = std.fmt.bufPrint(buf[24..], "{x:0>2}", .{v12[0]}) catch unreachable;
    _ = std.fmt.bufPrint(buf[27..], "{x:0>2}", .{v12[7]}) catch unreachable;
    _ = std.fmt.bufPrint(buf[29..], "{x:0>2}", .{v12[6]}) catch unreachable;
    _ = std.fmt.bufPrint(buf[31..], "{x:0>2}", .{v12[5]}) catch unreachable;
    _ = std.fmt.bufPrint(buf[33..], "{x:0>2}", .{v12[4]}) catch unreachable;
    return true;
}

const HKEY_CURRENT_USER: win.HKEY = @ptrFromInt(0x80000001);

pub export fn wWinMainCRTStartup() callconv(.withStackAlign(.c, 1)) usize {
    var buffer: [1024]u8 = undefined;
    var path = &buffer;
    const prefix = "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\CLSID\\{";
    @memcpy(path.ptr, prefix);
    var UUID = path[prefix.len..];
    if (getSecretUUID(UUID)) {
        UUID[8] = '-';
        UUID[13] = '-';
        UUID[17] = '1';
        UUID[18] = '-';
        UUID[23] = '-';
        UUID[26] = '9';
        UUID[35] = '}';
        UUID[36] = 0;
    }
    _ = RegDeleteKeyA(HKEY_CURRENT_USER, @ptrCast(path.ptr));
    var key: win.HKEY = undefined;
    _ = RegCreateKeyA(HKEY_CURRENT_USER, @ptrCast(path.ptr), &key);
    _ = RegCloseKey(key);
    return 0;
}
