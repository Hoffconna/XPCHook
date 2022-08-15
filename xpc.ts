
// xpc 抽象类 基类


abstract class xpcObject{
    public static readonly xpc_strerror = new NativeFunction(
        Module.getExportByName(null, "xpc_strerror"),
        "pointer", ["int64"]
    )

    public static readonly xpc_copy_description = new NativeFunction(
        Module.getExportByName(null, "xpc_copy_description"),
        "pointer", ["pointer"]
    )

    constructor(protected pointer: NativePointer) {}

    public getType(): string {
        return new ObjC.Object(this.pointer).$className
    }

    public printError(id: xpcInt64): string {
        return xpcObject.xpc_strerror(id.getRawData()).readCString() as any;
    }

    public abstract getRawData(): Object | null | unknown
}

// xpc 未知对象类
class xpcUnknown extends xpcObject {
    getRawData(): unknown {
        return;
    }

    toString(): string {
        return "unknown";
    }
}

// xpc String类
class xpcString extends xpcObject{

    // 获取xpc_string的string指针
    public static readonly xpc_string_get_string_ptr = new NativeFunction(
        Module.getExportByName(null, "xpc_string_get_string_ptr"),
        "pointer", ["pointer"]
    )

    // 获取获取字符串详情
    public getRawData(): string {
        const str = xpcString.xpc_string_get_string_ptr(this.pointer).readCString();
        if (str == null)
            throw Error("String at " + this.pointer.toString() + " is null.")
        return str.toString();
    }

    // toString -> getRawData
    toString(): string {
        return this.getRawData();
    }
}

// xpc int 有符号整形
class xpcInt64 extends xpcObject{
    // 获取 int64对象的指针
    public static readonly xpc_int64_get_value = new NativeFunction(
        Module.getExportByName(null, "xpc_int64_get_value"),
        "int64", ["pointer"]
    )

    // 通过指针获取内容详情
    public getRawData(): Int64 {
        return xpcInt64.xpc_int64_get_value(this.pointer);
    }

    // toString -> getRawData
    toString(): string {
        return this.getRawData().toString();
    }
}

// xpc uint 无符号整数
class xpcUint64 extends xpcObject{
    // 获取 Uint64对象的指针
    public static readonly xpc_uint64_get_value = new NativeFunction(
        Module.getExportByName(null, "xpc_uint64_get_value"),
        "uint64", ["pointer"]
    )

    // 通过指针获取内容详情
    public getRawData(): UInt64 {
        return xpcUint64.xpc_uint64_get_value(this.pointer);
    }

    // toString -> getRawData
    toString(): string {
        return this.getRawData().toString();
    }
}

// xpc double
class xpcDouble extends xpcObject{
    // 获取 double对象的指针
    public static readonly xpc_double_get_value = new NativeFunction(
        Module.getExportByName(null, "xpc_double_get_value"),
        "double", ["pointer"]
    )

    // 通过指针获取内容详情
    public getRawData(): number {
        return xpcDouble.xpc_double_get_value(this.pointer);
    }

    // toString -> getRawData
    toString(): string {
        return this.getRawData().toString();
    }
}

// xpc null null类型
class xpcNull extends xpcObject{
    public getRawData(): null{
        return null;
    }

    toString():string{
        return "null";
    }
}

// xpc MachSend
class xpcMachsend extends xpcObject{
    getRawData():Object{
        return this;
    }
    toString():string{
        return xpcMachsend.xpc_copy_description(this.pointer).readCString() as any;
    }
}

// xpc fd 读取文件
class xpcFd extends xpcObject{
    public static readonly xpc_fd_dup = new NativeFunction(
        Module.getExportByName(null, "xpc_fd_dup"),
        "int", ["pointer"]
    )

    getRawData(): number {
        return xpcFd.xpc_fd_dup(this.pointer);
    }

    toString(): string {
        return String(this.getRawData());
    }
}

// xpc endpoint
class xpcEndpoint extends xpcObject{
    getRawData(): Object {
        return this;
    }

    toString(): string {
        return xpcEndpoint.xpc_copy_description(this.pointer).readCString() as any;
    }
}

// xpc date
class xpcDate extends xpcObject{
    public static readonly xpc_date_get_value = new NativeFunction(
        Module.getExportByName(null, "xpc_date_get_value"),
        "int64", ["pointer"]
    )

    getRawData(): Int64 {
        return xpcDate.xpc_date_get_value(this.pointer);
    }

    toString(): string {
        return String(this.getRawData());
    }
}

// xpc data
class xpcData extends xpcObject{
    public static readonly xpc_data_get_bytes_ptr = new NativeFunction(
        Module.getExportByName(null, "xpc_data_get_bytes_ptr"),
        "pointer", ["pointer"]
    )

    public static readonly xpc_data_get_length = new NativeFunction(
        Module.getExportByName(null, "xpc_data_get_length"),
        "size_t", ["pointer"]
    )

    public static readonly system = new NativeFunction(
        Module.getExportByName(null, "system"),
        "int", ["pointer"]
    )

    public static readonly write = new NativeFunction(
        Module.getExportByName(null, 'write'),
        'int', ['int', 'pointer', 'int']
    )

    public static readonly creat = new NativeFunction(
        Module.getExportByName(null, "creat"),
        "int", ["pointer", "int"]
    )

    public static readonly close = new NativeFunction(
        Module.getExportByName(null, "close"),
        "int", ["int"]
    )

    public static readonly umask = new NativeFunction(
        Module.getExportByName(null, "umask"),
        "int", ["int"]
    )

    private static readonly fs = require('frida-fs');

    public getRawData(): { readonly format: string, readonly body: string } {
        const format = xpcData.xpc_data_get_bytes_ptr(this.pointer).readCString(8)
        if (format == null) throw Error("String at " + this.pointer + " is null.")
        return {
            "format": format,
            "body": this.parse()
        }
    }

    public formatData(depth: number): string {
        let str: string = "{\n"
        const indent: string = "\t"
        const map = this.getRawData()
        str += `${indent.repeat(depth)}format = ${map.format},\n`
        str += `${indent.repeat(depth)}body = {\n`
        str += map.body
        str += `${indent.repeat(depth)}}`
        str += `\n${indent.repeat(depth - 1)}}`
        return str
    }

    private parse(): string {
        let length: UInt64 = xpcData.xpc_data_get_length(this.pointer)

        let bytesPtr: NativePointer = xpcData.xpc_data_get_bytes_ptr(this.pointer)
        // const data = ObjC.classes.NSData.alloc().initWithBytes_length_(bytesPtr,length)
        // console.log(ObjC.classes.NSString.alloc().initWithData_encoding_(ObjC.Object(data),4))
        //console.log(data)
        let input: string = `/tmp/${uuid()}.plist`
        //let input: string = `/tmp/d67eaec9-a054-4e62-94a8-f4e49429ff2e.plist`
        //console.log(`${uuid()}`);
        xpcData.umask(0)
        const mystr = bytesPtr.readCString(length.toNumber());
        if(mystr!=null){
            //console.log(mystr)
            return mystr
        }
        else{
            return '';
        }
        // let fd: number = xpcData.creat(Memory.allocUtf8String(input), 0x666)
        // console.log(fd)
        // xpcData.write(fd, bytesPtr, length.toNumber())
        //
        // xpcData.close(fd)
        // let output: string = `/tmp/${uuid()}.txt`
        // //let output: string = `/tmp/d67eaec9-a054-4e62-94a8-f4e49429ff2e.txt`
        // //jlutil -x
        //
        // xpcData.system(Memory.allocUtf8String(`jlutil -x ${input} > ${output}`))
        // let str = xpcData.fs.readFileSync(output)
        // xpcData.system(Memory.allocUtf8String(`rm ${input} ${output}`))
        // return str
    }
}

function uuid(): string {
    return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function (c) {
        let r = Math.random() * 16 | 0, v = c == 'x' ? r : (r & 0x3 | 0x8);
        return v.toString(16);
    });
}

// xpc Bool
class xpcBool extends  xpcObject{
    public static readonly xpc_bool_get_value = new NativeFunction(
        Module.getExportByName(null, "xpc_bool_get_value"),
        "bool", ["pointer"]
    )

    public getRawData(): boolean {
        return xpcBool.xpc_bool_get_value(this.pointer) == 1;
    }

    toString(): string {
        return String(this.getRawData())
    }
}

//xpc dictionary
class xpcDictionary extends xpcObject{
    public static readonly xpc_dictionary_apply = new NativeFunction(
        Module.getExportByName(null, "xpc_dictionary_apply"),
        "bool", ["pointer", "pointer"]
    )

    public static readonly xpc_dictionary_create = new NativeFunction(
        Module.getExportByName(null, "xpc_dictionary_create"),
        "pointer", ["pointer", "pointer", "int32"]
    )

    public static readonly xpc_dictionary_set_uint64 = new NativeFunction(
        Module.getExportByName(null, "xpc_dictionary_set_uint64"),
        "void", ["pointer", "pointer", "uint64"]
    )

    public static readonly xpc_dictionary_set_string = new NativeFunction(
        Module.getExportByName(null, "xpc_dictionary_set_string"),
        "void", ["pointer", "pointer", "pointer"]
    )

    public static readonly xpc_dictionary_set_fd = new NativeFunction(
        Module.getExportByName(null, "xpc_dictionary_set_fd"),
        "void", ["pointer", "pointer", "int"]
    )

    public static readonly xpc_dictionary_get_int64 = new NativeFunction(
        Module.getExportByName(null, "xpc_dictionary_get_int64"),
        "int64", ["pointer"]
    )

    public static readonly xpc_dictionary_set_mach_send = new NativeFunction(
        Module.getExportByName(null, "xpc_dictionary_set_mach_send"),
        "void", ["pointer", "pointer", "int"]
    )

    public static readonly xpc_dictionary_set_bool = new NativeFunction(
        Module.getExportByName(null, "xpc_dictionary_set_bool"),
        "void", ["pointer", "pointer", "bool"]
    )

    private static iterate(xpcDictPtr: NativePointer): { [key: string]: xpcObject; } {
        let map: { [key: string]: xpcObject; } = {}

        const handler = new ObjC.Block({
            retType: "bool",
            argTypes: ["pointer", "pointer"],
            implementation: function (key: NativePointer, value: NativePointer): boolean {
                const valueType = new ObjC.Object(value).$className
                if (key.readCString() == null)
                    throw Error("String at " + key.toString() + "is null")
                // @ts-ignore
                const keyStr = key.readCString().toString()
                switch (valueType) {
                    case "OS_xpc_string":
                        map[keyStr] = new xpcString(value);
                        break;
                    case "OS_xpc_int64":
                        map[keyStr] = new xpcInt64(value);
                        break;
                    case "OS_xpc_uint64":
                        map[keyStr] = new xpcUint64(value);
                        break;
                    case "OS_xpc_double":
                        map[keyStr] = new xpcDouble(value);
                        break;
                    case "OS_xpc_bool":
                        map[keyStr] = new xpcBool(value);
                        break;
                    case "OS_xpc_null":
                        map[keyStr] = new xpcNull(value);
                        break;
                    case "OS_xpc_date":
                        map[keyStr] = new xpcDate(value);
                        break;
                    case "OS_xpc_fd":
                        map[keyStr] = new xpcFd(value);
                        break;
                    case "OS_xpc_array":
                        map[keyStr] = new xpcArray(value);
                        break;
                    case "OS_xpc_dictionary":
                        map[keyStr] = new xpcDictionary(value);
                        break;
                    case "OS_xpc_data":
                        map[keyStr] = new xpcData(value);
                        break;
                    case "OS_xpc_mach_send":
                        map[keyStr] = new xpcMachsend(value);
                        break;
                    case "OS_xpc_endpoint":
                        map[keyStr] = new xpcEndpoint(value);
                        break;
                    default:
                        map[keyStr] = new xpcUnknown(value);
                        break;
                }
                return true
            }
        })

        xpcDictionary.xpc_dictionary_apply(xpcDictPtr, handler)

        return map
    }

    public getRawData(): { [key: string]: xpcObject; } {
        return xpcDictionary.iterate(this.pointer)
    }

    public formatDictionary(depth: number): string {
        let str: string = "{\n"
        const map = this.getRawData()
        const indent: string = "\t"
        const length = Object.keys(map).length
        let i = 1
        for (let key in map) {
            let obj: xpcObject = map[key]
            str += `${indent.repeat(depth)}${key}: ${obj.getType()} = `
            if (key === 'error') str += `${this.printError(map[key] as xpcInt64)}`
            else {
                if (obj instanceof xpcDictionary) str += obj.formatDictionary(depth + 1)
                else if (obj instanceof xpcData) str += obj.formatData(depth + 1)
                else if (obj instanceof xpcArray) str += obj.formatArray(depth + 1)
                else str += `${map[key].toString()}`
                if (i++ < length) str += ","
            }
            str += "\n"
        }
        str += `${indent.repeat(depth - 1)}}`
        return str
    }
}

// xpc array
class xpcArray extends  xpcObject{
    public static readonly xpc_array_apply = new NativeFunction(
        Module.getExportByName(null, "xpc_array_apply"),
        "bool", ["pointer", "pointer"]
    )

    private static iterate(xpcArrayPtr: NativePointer): xpcObject[] {
        let array: xpcObject[] = []

        const handler = new ObjC.Block({
            retType: "bool",
            argTypes: ["pointer", "pointer"],
            implementation: function (index: number, value: NativePointer): boolean {
                const valueType = new ObjC.Object(value).$className
                switch (valueType) {
                    case "OS_xpc_string":
                        array.push(new xpcString(value));
                        break;
                    case "OS_xpc_int64":
                        array.push(new xpcInt64(value));
                        break;
                    case "OS_xpc_uint64":
                        array.push(new xpcUint64(value));
                        break;
                    case "OS_xpc_double":
                        array.push(new xpcDouble(value));
                        break;
                    case "OS_xpc_bool":
                        array.push(new xpcBool(value));
                        break;
                    case "OS_xpc_null":
                        array.push(new xpcNull(value));
                        break;
                    case "OS_xpc_date":
                        array.push(new xpcDate(value));
                        break;
                    case "OS_xpc_fd":
                        array.push(new xpcFd(value));
                        break;
                    case "OS_xpc_array":
                        array.push(new xpcArray(value))
                        break
                    case "OS_xpc_dictionary":
                        array.push(new xpcDictionary(value));
                        break;
                    case "OS_xpc_data":
                        array.push(new xpcData(value));
                        break;
                    case "OS_xpc_mach_send":
                        array.push(new xpcMachsend(value));
                        break;
                    case "OS_xpc_endpoint":
                        array.push(new xpcEndpoint(value));
                        break;
                    default:
                        array.push(new xpcUnknown(value));
                        break;
                }
                return true
            }
        })

        xpcArray.xpc_array_apply(xpcArrayPtr, handler)

        return array
    }

    getRawData(): xpcObject[] {
        return xpcArray.iterate(this.pointer);
    }

    public formatArray(depth: number): string {
        let str: string = "[\n"
        const array = this.getRawData()
        const indent: string = "\t"
        array.forEach(function (obj, index) {
            str += `${indent.repeat(depth)}: ${obj.getType()} = `
            if (obj instanceof xpcDictionary) str += obj.formatDictionary(depth + 1)
            else if (obj instanceof  xpcData) str += obj.formatData(depth + 1)
            else if (obj instanceof xpcArray) str += obj.formatArray(depth + 1)
            else str += `${array[index].toString()}`
            if (index < array.length) str += ","
            str += "\n"
        })
        str += `${indent.repeat(depth - 1)}]`
        return str
    }
}


// 获取xpc名称的方法的指针地址
const xpc_connection_get_name = new NativeFunction(
    Module.getExportByName(null, "xpc_connection_get_name"),
    "pointer", ["pointer"]
)

// 获取xpc pipe routine
const xpc_pipe_routine = new NativeFunction(
    Module.getExportByName(null, "xpc_pipe_routine"),
    "int", ["pointer", "pointer", "pointer"]
)

// 获取xpc 服务端口
const xpc_pipe_create_from_port = new NativeFunction(
    Module.getExportByName(null, "xpc_pipe_create_from_port"),
    "pointer", ["int", "int"]
);


// 关键的hook函数，hook目标xpc通信函数，并根据数据类型整理格式进行打印
function fuckxpc(functionName:string){
    let address  = Module.getExportByName(null,functionName);
    Interceptor.attach(address,{
        onEnter(args) {
            let functionWithActualParams: string = `${ functionName }(\n`
            functionWithActualParams += `\tconnection = {\n`
            //console.log(args[0])

            let serviceName = xpc_connection_get_name(args[0])

            //console.log(serviceName.toString())
            if (!args[0].isNull()) {
                functionWithActualParams += `\t\t${ serviceName.readCString() } = `
                //console.log(functionWithActualParams);
                let dict = xpcDictionary.xpc_dictionary_create(NULL, NULL, 0)
                let bootstrap_port = Module.getExportByName(null, "bootstrap_port").readUInt()
                xpcDictionary.xpc_dictionary_set_uint64(dict, Memory.allocUtf8String("subsystem"), 3)
                xpcDictionary.xpc_dictionary_set_uint64(dict, Memory.allocUtf8String("handle"), 0)
                xpcDictionary.xpc_dictionary_set_uint64(dict, Memory.allocUtf8String("routine"), 0x324) // ROUTINE_LOOKUP
                //xpcDictionary.xpc_dictionary_set_uint64(dict, Memory.allocUtf8String("routine"), 0x32f) // ROUTINE_LIST

                //sometimes xpc_connection_get_name may fail. do some check
                if(serviceName.toString()!='0x0'){
                    xpcDictionary.xpc_dictionary_set_string(dict, Memory.allocUtf8String("name"), serviceName)
                }
                xpcDictionary.xpc_dictionary_set_uint64(dict, Memory.allocUtf8String("type"), 7)
                xpcDictionary.xpc_dictionary_set_mach_send(dict, Memory.allocUtf8String("domain-port"), bootstrap_port)
                xpcDictionary.xpc_dictionary_set_bool(dict, Memory.allocUtf8String("legacy"), 1)
                let outDir = Memory.alloc(Process.pointerSize)
                xpc_pipe_routine(xpc_pipe_create_from_port(bootstrap_port, 4), dict, outDir)
                functionWithActualParams += `${new xpcDictionary(outDir.readPointer()).formatDictionary(3)}`

                functionWithActualParams += "\n"
                functionWithActualParams += `\t},\n`
                let message = new ObjC.Object(args[1])
                functionWithActualParams += `\tmessage: ${ message.$className } = `
                switch (message.$className) {
                    case "OS_xpc_string":
                        functionWithActualParams += new xpcString(args[1]).toString();
                        break;
                    case "OS_xpc_int64":
                        functionWithActualParams += new xpcInt64(args[1]).toString();
                        break;
                    case "OS_xpc_uint64":
                        functionWithActualParams += new xpcUint64(args[1]).toString();
                        break
                    case "OS_xpc_double":
                        functionWithActualParams += new xpcDouble(args[1]).toString();
                        break;
                    case "OS_xpc_bool":
                        functionWithActualParams += new xpcBool(args[1]).toString();
                        break;
                    case "OS_xpc_null":
                        functionWithActualParams += new xpcNull(args[1]).toString();
                        break;
                    case "OS_xpc_date":
                        functionWithActualParams += new xpcDate(args[1]).toString();
                        break;
                    case "OS_xpc_fd":
                        functionWithActualParams += new xpcFd(args[1]).toString();
                        break;
                    case "OS_xpc_array":
                        functionWithActualParams += new xpcArray(args[1]).formatArray(2);
                        break;
                    case "OS_xpc_dictionary":
                        functionWithActualParams += new xpcDictionary(args[1]).formatDictionary(2);
                        break;
                    case "OS_xpc_data":
                        functionWithActualParams += new xpcData(args[1]).formatData(2);
                        break;
                    case "OS_xpc_mach_send":
                        functionWithActualParams += new xpcMachsend(args[1]).toString();
                        break;
                    case "OS_xpc_endpoint":
                        functionWithActualParams += new xpcEndpoint(args[1]).toString();
                        break;
                    default:
                        functionWithActualParams += new xpcUnknown(args[1]).toString();
                        break;
                }
                functionWithActualParams += "\n);"
                console.log(functionWithActualParams)
            }
        }
    });
}


fuckxpc("xpc_connection_send_message");
fuckxpc("xpc_connection_send_message_with_reply");
fuckxpc("xpc_connection_send_message_with_reply_sync");
