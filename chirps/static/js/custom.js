
/**
 * @args
 * postUrl: url to post to (/approve or /reject)
 * chirpId: id of chirp to handle
 * ownerId: id of user the chirp belongs to
 */
function handleChirp(event) {
    $.ajax({
        type: 'POST',
        url: event.data.postUrl,
        contentType: 'application/x-www-form-urlencoded; charset=UTF-8',
        data: {
            chirpId: event.data.chirpId,
            userId: event.data.userId,
            chirpTitle: event.data.chirpTitle},
        success: function(response) {
            var chirpRowId = '#chirp-' + event.data.chirpId;
            $(chirpRowId).remove();
            alertMsg('success', response);
        }
    });
}

function alertMsg(status, message) {
    var alertContainer = $('#alert-area');
    var newAlert = $('<div></div>').addClass('alert').attr('role', 'alert');
    if (status == 'success') {
        newAlert.addClass('alert-success');
        newAlert.text(message);
        alertContainer.append(newAlert);
        setTimeout(function () {
            newAlert.addClass('fade');
            newAlert.remove();
        }, 3000);
    }
}


function main() {
    var approveButtons = $('.approveBtn');
    var rejectButtons = $('.rejectBtn');

    for (var i = 0; i < approveButtons.length; i++) {
        btn = approveButtons[i];
        $(btn).on('click', {
                postUrl: '/approve',
                chirpTitle: btn.parentNode.dataset.chirpTitle,
                chirpId: btn.parentNode.dataset.chirpId,
                userId: btn.parentNode.dataset.userId,
            }, handleChirp);
    }

    for (var i = 0; i < rejectButtons.length; i++) {
        btn = rejectButtons[i];
        $(btn).on('click', {
                postUrl: '/reject',
                chirpTitle: btn.parentNode.dataset.chirpTitle,
                chirpId: btn.parentNode.dataset.chirpId,
                userId: btn.parentNode.dataset.userId,
            }, handleChirp);
    }

};

document.addEventListener('DOMContentLoaded', function(e) {
    main();
});
