const std = @import("std");
const win = std.os.windows;
const DWORD = win.DWORD;
const UINT = win.UINT;

const Address = struct {
    address: ?*anyopaque,
    const Self = @This();
    pub fn of(addressLike: anytype) Self {
        var realAddress: ?*anyopaque = undefined;
        switch (@typeInfo(@TypeOf(addressLike))) {
            .Int, .ComptimeInt => {
                realAddress = @ptrFromInt(addressLike);
            },
            .Pointer => |ptr| {
                if (ptr.size == .Slice) {
                    realAddress = @ptrFromInt(@intFromPtr(addressLike.ptr));
                } else {
                    realAddress = @ptrFromInt(@intFromPtr(addressLike));
                }
            },
            else => unreachable,
        }
        return Self{
            .address = realAddress,
        };
    }
    fn toInt(this: Self) usize {
        return @intFromPtr(this.address);
    }
    fn toPtrOf(this: Self, comptime ptrType: type) ptrType {
        if (@typeInfo(ptrType) != .Pointer)
            @compileError("Only pointer type is accepted in `Address.toPtrOf()`");
        return @alignCast(@ptrCast(this.address));
    }
};

extern fn GetSystemFirmwareTable(FirmwareTableProviderSignature: DWORD, FirmwareTableID: DWORD, pFirmwareTableBuffer: usize, BufferSize: DWORD) callconv(win.WINAPI) UINT;

extern fn RegDeleteKeyA(hKey: win.HKEY, lpSubKey: win.LPCSTR) callconv(win.WINAPI) win.LSTATUS;

extern fn RegCreateKeyA(hKey: win.HKEY, lpSubKey: win.LPCSTR, phkResult: *win.HKEY) callconv(win.WINAPI) win.LSTATUS;
extern fn RegCloseKey(hKey: win.HKEY) callconv(win.WINAPI) win.LSTATUS;
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

fn HIWORD32(dword: u32) u16 {
    return @truncate(dword >> 16);
}
fn HIWORD64(dword: u64) u16 {
    return @truncate(dword >> 48);
}

fn getSecretUUID(buf: []u8) void {
    const RSMB = comptime strToU32("RSMB");
    const defaultUUID = "yyyy yyyy}\x00";
    var sizeOfBuffer = GetSystemFirmwareTable(RSMB, 0, 0, 0);
    if (sizeOfBuffer == 0) {
        @memcpy(buf.ptr, defaultUUID);
        return;
    }
    var buffer: [4096]i8 = undefined;
    const bytesWritten = GetSystemFirmwareTable(RSMB, 0, Address.of(&buffer).toInt(), sizeOfBuffer);
    if (bytesWritten == 0) {
        @memcpy(buf.ptr, defaultUUID);
        return;
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
        return;
    }
    if (i == 0) {
        @memcpy(buf.ptr, defaultUUID);
        return;
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
    // _ = std.fmt.bufPrint(buf, "{x:0>8}-{x:0>4}{x:0>4}-{x:0>2}{x:0>2}{x:0>2}{x:0>2}-{x:0>2}{x:0>2}{x:0>2}{x:0>2}", .{
    //     firstPart[0],
    //     secPart[1],
    //     secPart[0],
    //     v12[3],
    //     v12[2],
    //     v12[1],
    //     v12[0],
    //     v12[7],
    //     v12[6],
    //     v12[5],
    //     v12[4],
    //     //
    // }) catch unreachable;
}

const HKEY_CURRENT_USER = Address.of(0x80000001).toPtrOf(win.HKEY);

pub export fn wWinMainCRTStartup() callconv(.C) usize {
    @setAlignStack(16);
    var buffer: [1024]u8 = undefined;
    var path = &buffer;
    const prefix = "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\CLSID\\{";
    @memcpy(path.ptr, prefix);
    var UUID = path[prefix.len..];
    getSecretUUID(UUID);
    UUID[8] = '-';
    UUID[13] = '-';
    UUID[17] = '1';
    UUID[18] = '-';
    UUID[23] = '-';
    UUID[26] = '9';
    UUID[35] = '}';
    UUID[36] = 0;
    //std.debug.print("{s}", .{path});
    _ = RegDeleteKeyA(HKEY_CURRENT_USER, @ptrCast(path.ptr));
    var key: win.HKEY = undefined;
    _ = RegCreateKeyA(HKEY_CURRENT_USER, @ptrCast(path.ptr), &key);
    _ = RegCloseKey(key);
    return undefined;
}
